# `debugproto.rs` API Reference

`src/debugproto.rs` implements Rugra's native equivalent of Ghidra's
pre-decompiler debug-import boundary. Ghidra's DWARF analyzer writes declared
function prototypes into the Program database; the C++ decompiler subsequently
receives a locked `FuncProto`. Rugra now parses concrete ELF DWARF subprograms,
follows `DW_AT_abstract_origin` / `DW_AT_specification`, preserves formal
parameter order, names, resolved scalar/pointer types and varargs, asks the
bound compiler model to assign register or stack storage, and locks
input/output/model state before Actions run. The current production evidence
is scoped to the locked `x86-64-gcc.cspec`; it is not a generic ABI claim.

It also imports DWARF global variables (`DWARF-TYPE-IMPORT-0001`):
`DebugGlobalDatabase::parse_elf` walks `DW_TAG_variable` DIEs whose
`DW_AT_location` is exactly `DW_OP_addr <addr>` and records each global's
storage address, name, and resolved data type. `address_pointer_map` projects
those globals into the `Funcdata::global_struct_ptrs` seeding form: the type
of an address constant that references the global, i.e. a pointer to the
declared variable type with C array decay (0x17660 `glob_expand` →
`URLGlob **`, 0x17520 `config` → `Configurable *`, 0x17680 `glob_buffer`
→ `char *`).

`DebugGlobalDatabase::seed_global_locked` (`GLOBWORD-C5-GLOBAL-TYPEFLOW-0001`)
is the driver-side projection of the DWARF front end's committed-data-type
semantic: Ghidra's analyzer creates Data with a locked-in type, the decompiler
interface exports it as ATTRIB_TYPELOCK, and `Symbol::decodeHeader`
(database.cc:439-442) folds it into the Symbol's typelock flag. It seeds one
global into the query-channel `Database` (`add_symbol_mapped` + TYPELOCK).
Both typelock-gated consumers — `SymbolEntry::updateType` (database.cc:135-141,
reached through `Varnode::setSymbolProperties` varnode.cc:413) and
`ActionInferTypes::buildLocaltypes`' exact-piece branch (coreaction.cc:5021-
5027) — depend on the flag to attach the global Symbol's DWARF type onto the
address varnode `RuleLoadVarnode` materializes (ruleaction.cc:4293). Without
it the global's value degrades to raw offsets in the C output
(`*(int *)(glob_expand + 0x128)` instead of `glob_expand->size`).

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
- `LibcSignatureTable::locked_proto(name, model_carrier, type_names)` — builds
  a clean callee `FuncProto` that shares the carrier's resolved model, then
  routes the declared types through `FuncProto::setPieces` and that model's
  `assignParameterStorage`. Input, output, and model are all locked. Returns
  `Ok(None)` for unknown imports and `Err` when the compiler model cannot
  assign the prototype. A seventh scalar input can therefore spill to stack;
  aggregate/ModelRule and non-x86 behavior remain unproved.
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
  boolean/int). The locked analyzer's character distinction is also retained:
  core `char`/`signed char` and the `DW_ATE_signed_char` fallback become a
  `CHARTYPE`/`SUB_INT_CHAR` datatype, while `DW_ATE_unsigned_char` remains the
  ordinary unsigned `uchar` type;
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
- typedefs/qualifiers clone and rename the complete resolved datatype instead
  of reducing it to a base `(size, metatype)` pair. This preserves character
  flags/submeta and pointer/array/composite shape. Rugra still has no
  `TypeTypedef` variant or importer-side TypeFactory registry identity;
- recursive type graphs (`FILE` → `struct _IO_FILE` → `_chain FILE *`) break
  at the back edge with a shallow named projection (name/size/metatype, no
  fields), mirroring how Ghidra's two-phase type manager exposes an
  already-created type before its members are filled.

This is the first `DWARF-PROTO-0001` closure, not a claim of complete DWARF or
prototype recovery. Cross-compilation-unit references, location-list state,
aggregate ModelRules, split DWARF and non-x86 compiler specs remain explicitly
unsupported. Scalar stack parameters are now assigned by the bound model, but
that narrow result does not prove aggregate/join/hidden-return behavior.
Stripped-binary inference remains
`PARAM-RECOVERY-0001`. The module and signature pipeline therefore remain L2.

The current curl regression input has SHA-256
`4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`.
Rust-side import tests cover `GetStr` (2 fixed parameters), `myprogress` (5),
`helpf` (1 plus varargs), the optimized `getparameter` definition (4 via
`DW_AT_abstract_origin`), locked zero-input `hugehelp`, and the five DWARF
globals of the curl fixture (`config`, `save`, `beenhere`, `glob_buffer`,
`glob_expand`) including the `URLGlob` 304-byte layout (literal char*[10] @0,
pattern URLPattern[9] @80, size int @296) and the `&global` pointer map.
This is useful regression evidence, but it is not a complete Ghidra
DWARF-analyzer oracle fixture; the importer remains `NO_ORACLE` under mechanism
B2. A fresh production GetStr differential does prove the resulting visible
character-token projection (`*value != '\0'`) against the locked 12.0.4 golden;
it does not prove the importer state or factory-identity closure.

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

## 2026-08-28：零参数不改变调用约定模型

### `DebugPrototypeDatabase::apply` 的模型状态（fspec.cc:4690-4698/4776）

锁定的 Program-database 签名经 `FuncProto::decode` 进入反编译器：ATTRIB_MODEL
携带平台侧调用约定名，无法识别的名字走 `createUnknownModel`
（fspec.cc:4697 → architecture.cc:1159-1166），得到克隆 defaultfp 行为、
`isUnknown()=true`、且名字 "unknown" 不打印进声明的 `UnknownProtoModel`；
空参列表的 voidlock 置位 modellock（fspec.cc:4776）。

旧实现按 `parameters.is_empty()` 强制写入 `unknown`，这不是 Ghidra 机制，现已
删除。Program database 编码的 `ATTRIB_MODEL` 决定是否创建
`UnknownProtoModel`；`voidinputlock` 只锁定空输入列表，不替换已经绑定的模型。
因此零参数和带参数原型都保留 `model_carrier` 的共享模型身份。

对应回归测试改为 `void_signature_dwarf_prototype_keeps_bound_model`。真正显式
unknown 模型的 warning 仍由 coreaction 的独立测试覆盖；本适配层没有真实
Program database 双侧 fixture，整体继续是 `NO_ORACLE` / L2。

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

- `DebugPrototypeDatabase::locked_callsite_proto(entry, model_carrier)`：同一
  Program-数据库边界的调用点半边。`model_carrier` 提供模型
  ——与 callee 自身 `Funcdata` 绑定的 Architecture defaultfp 相同（driver 传
  `fd.funcp`，FUNCPROTO-MODEL-BIND-0001 的 set_arch 绑定后）。锁配方与
  `apply` 完全一致（共享 `locked_proto` 构建器，fspec.cc:3843-3852 setPieces
  语义）：模型驱动的存储、DW_AT_name 才 NAME_LOCKED、input/output/model
  三锁，且参数数量不改写模型。`Ok(None)` = 该地址无 DWARF 定义（thunk/
  导入：generic_clib 表或 active recovery 负责）。
- driver `link_call_specs`：libc 表未命中（thunk 地址无 DWARF 定义、DWARF
  函数名不在 24 条导入表内——两源按构造不相交）后查 DWARF，命中即整体替换
  callspec `prototype`。`[PREPASS]` 日志新增 locked DWARF signatures 计数。

### 可观察效果与边界（诚实账）

- main：`extraout_var` 声明位次变化（14 个 DWARF 锁定 callee 的 output_type
  _locked 改变了 funcLinkOutput 的锁定路径与 active-output trial 集合）。
  **调用实参个数不变**：`curl_version(lVar50,in_RDX,argv,argc,in_R8,in_R9)`
  仍 6 个试验参数——实参个数由 CALL op 的 input varnodes 决定
  （printc opCall 按 `op->numInput()-1` 渲染，printc.cc:610-624）。
  `ActionFuncLink::func_link_input` 现读取锁定原型参数并使用模型分配的
  register/stack 存储，不再读取硬编码 ABI 表；后续 trial commit/trim 路径仍
  有独立残差。
- aggregate/join/hidden-return 参数仍受未移植 ModelRules、TypeFactory identity
  与完整 Address 身份约束；不能从 scalar stack case 外推。

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
generic_clib 的核心 `char` 现在用字符构造器，
而不是仅名称相同的普通 1-byte `TYPE_INT`；因此 `strdup` 等锁定签名的 pointee
保留 `isCharPrint()`。

## 2026-08-29：PTRSUB-TYPED-DECL-RESIDUAL-0001 — 解析指针改匿名（Ghidra 对齐）

`parse_c_type` 的嵌套指针层与 DWARF 边界的 `pointer_type`/DW_TAG_array_type
数组构建此前给类型附带组合显示名（`"char *"`/`"char **"`/`"char *[10]"`）。
Ghidra 的对应路径（`PointerModifier::modType` → `TypeFactory::getTypePointer`
3-arg，grammar.cc:2403-2411 / type.cc:3867-3875；`getTypeArray` type.cc:3902）
一律构造**匿名**类型——`"char *"` 是语法拼写不是类型身份。组合名使这些指针成为
**命名单层指针**，printc 忠实渲染为 `char * pcVar1`（oracle
printc_anonymous_pointer_decl_1204 named_ptr_contrast），偏离 golden 的匿名
多层钻取形 `char *pcVar1`。现在 `parse_c_type`/`pointer_type`/DWARF 数组均
构造匿名类型（`TypePointer::new`/空名 `TypeArray`），结构断言取代名称断言
（`libc_locked_proto...`/`curl_dwarf_globals...` 等测试已同步）。

## 2026-08-28：DEBUGPROTO-DWARF-CHAR-0001 — GetStr 字符类型边界

锁定输入 `examples/curl`（SHA-256
`8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`）中，
GetStr 的 `value` 参数沿 DWARF DIE `0x28c6 → 0x174 → 0x17f` 指向
`name=char,size=1,DW_ATE_signed_char`。Ghidra 12.0.4 的决定链为：

- `DWARFDataTypeManager.java:397-449` 先按 name/size/encoding compatibility
  查核心类型，再做 encoding fallback；`:426` 选择 `baseDataTypeChar`，`:427`
  明确把 unsigned-char 选择为普通 `baseDataTypeUchar`；
- `PcodeDataTypeManager.java:1180-1200,1238-1253` 为核心 CharDataType 编码
  `char=true`；
- C++ `type.cc:4511-4523` 解码为 factory-owned `TypeChar`，其
  `chartype`/`SUB_INT_CHAR` 使 `isCharPrint()` 为真。

旧 importer 只构造 `TypeBase::new(name,1,TYPE_INT)`，名称虽为 `char`，flags
仍为 0；read-facing 打印路径因此正确地输出了数值 `0`。现在
`dwarf_base_type` 保留 signed-character/core-char 分类，`parse_c_type("char")`
也使用字符构造器，typedef/qualifier clone 保留完整 flags/submeta 和结构形状。

定向 Rust 回归覆盖实际 GetStr DWARF 参数、libc `strdup` pointee，以及
typedef/qualifier 的字符语义与 pointer shape。fresh release 生产路径随后得到：

```c
if ((value != (char *)0x0) && (*value != '\0')) {
```

`compare_ghidra.py --func GetStr -v` 报告 skeleton identical、defects=0、
numbering=0。这个结果只把 GetStr 的最终可见字符投影升为 `MATCH`。完整 importer
仍有明确残差：尚未实现 Java 的全量 name-first base-type 表、Program database
typedef identity、Architecture TypeFactory `findAdd`/canonical cache，以及
signed/unsigned/UTF/非标准 data-organization 的双侧矩阵；状态保持
`NO_ORACLE`/L2。

## 2026-08-28：模型驱动签名存储边界

libc/DWARF producer 已删除手写 SysV resource 表：它们从当前 Architecture 的
model carrier 构造干净 callee prototype，再由 `setPieces` 调用模型的
`assignParameterStorage`。零参数只设置 void input lock，不再凭 arity 制造
UnknownProtoModel；真实参数名才置 NAME_LOCKED。

FuncLink bilateral fixture 会消费这些 producer 形成的 scalar register/stack
storage，但并没有运行真实 Ghidra Program database/analyzer importer。因此本
front-end adapter 本身仍为 `NO_ORACLE`/L2；aggregate ModelRules、非 x86、完整
ProtoStore codec 与错误状态均未获批准。

## 2026-08-30：HTTPD-URAM-SYMBOLIZE-0001 — PLT thunk 名与默认 FUN_ 符号导入

`ElfPltImports::parse_elf` 是 ELF PLT thunk 名导入边界（Ghidra Java
ELF/PLT analyzer 的 native 对应物）：`.plt.sec`/`.plt` 槽位按索引对应
`.rela.plt` JUMP_SLOT 重定位（第 i 项 ↔ `base + 16*i`，`.plt` 跳过解析器头
从 1 起），`.plt.got` 槽位逐个解码 `f2 ff 25 <disp32>` 尾巴并匹配拥有该
GOT 地址的 R_X86_64_GLOB_DAT 重定位。几何与匹配沿用 curl 驱动已锁定的实现
（原 examples/curl_decompile.rs 内联块，提炼为共享边界）；httpd witness：
slot 43 = 0x2a6d0 = `apr_app_initialize`，`.plt`@0x29020、`.plt.got`@0x2a400、
`.plt.sec`@0x2a420，317 个 JUMP_SLOT 全部解析。

`analyze_headless_function_symbol_name(vaddr, image_base)` 镜像 Java
SymbolManager 的默认函数符号策略：`FUN_` + analyzeHeadless image-base 地址
的 8 位零填充 hex（ET_DYN image 装载于 0x100000，golden 的共享尾块
0x2c520 → `FUN_0012c520`）。

消费链（对齐 flow.cc:656-672 `queryCall` → fspec.cc:4949-4960 `setFuncdata`
→ printc.cc:601-609 `opCall` 的 `fc->getName()`）：驱动把 thunk 名与未命名
call-target 的默认名种入 callpoint-symbol 替身表，`map_globals` 对已命名地址
经 has_symbol 门跳过 `uRam<offset>` 合成，`PrintC` 的 CPUI_CALL 臂按地址取名。
E2E（httpd 29 函数口径）：uRam 调用 87→0（82 thunk + 5 发现函数全部按 golden
拼写命名），skeleton 2278→2274，defects=0、numbering=0；curl 输出字节不变
（3090/0/0）。单元测试 3 项（slot 重定位映射、image-base 命名、非 ELF 拒绝）
锁 httpd 语料。前端 adapter 本身仍 `NO_ORACLE`/L2（无真实 Java analyzer
对拍；oracle 证据=12.0.4 headless golden 的 thunk/默认名拼写与计数）。
