# `userop.rs` API Reference

**源代码路径**: `src/userop.rs`
**Ghidra 对应**: `userop.hh` / `userop.cc` (1009行)
**状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——派生 userop 类型/selector/conflict/builtin 契约未闭合；SegmentOp 硬编码 `base<<4`，JumpAssist consumer 与真实 ActionSegmentize 缺失，Architecture/Flow 生产路径未安装 userops。正式门禁 `NO_ORACLE`。

## 模块说明

用户自定义 P-code 操作（CALLOTHER）管理。对应 Ghidra 的 `userop.hh`。

## 导出的公共 API

### `pub enum UserOpType`
用户操作类型（Unspecialized/Injected/VolatileRead/VolatileWrite/Segment/JumpAssist/StringData/Datatype）。

### `pub struct UserPcodeOp`
用户定义 P-code 操作的基础定义。对应 Ghidra `UserPcodeOp`。
- `new(name, type, index)` / `get_name()` / `get_type()` / `get_index()` / `get_display()`

### `pub struct UserOpManage`
所有注册用户操作的管理器。对应 Ghidra `UserOpManage`。
- `register_op(name, type) -> i32` / `get_op(index)` / `get_index_by_name(name)` / `num_ops()`

### Built-in IDs
`BUILTIN_STRINGDATA/VOLATILE_READ/VOLATILE_WRITE/MEMCPY/STRNCPY/WCSNCPY`

测试：userop::tests 3 个。

## 2026-06-26（续）：userop.rs 完善实现

新增完整 UserOpManage 和专用子类构造函数：
- `initialize_builtins()` — 初始化所有内置 CALLOTHER ID
- `register_builtin(name, id)` — 注册内置操作
- `get_op_mut(index)` — 可变访问
- `is_volatile_read/write(index)` — 检查类型
- `create_unspecialized/injected/volatile_read/volatile_write/segment/jump_assist` — 专用子类构造函数

测试：新增 2 个（initialize_builtins + create_specialized）。

### 2026-06-27（会话3 L1）：userop.cc 专用子类移植

移植 UserPcodeOp 的专用子类 + DatatypeUserOp：
- **DatatypeUserOp** — 提供 CALLOTHER 的输入/输出数据类型（get_output_local/get_input_local）
- **VolatileReadOp** — 易失性读操作（extract_annotation_size 返回 varnode size）
- **VolatileWriteOp** — 易失性写操作
- **SegmentOp** — 分段地址操作（x86 real mode far pointer）
- **JumpAssistOp** — 跳转表辅助操作（index2case/index2addr/defaultaddr/calcsize 注入 ID）
- **InternalStringOp** — 内部字符串操作

UserPcodeOp 新增：get_operator_name/extract_annotation_size/is_volatile_read/is_volatile_write/is_segment/is_jump_assist/is_injected/is_string_data。

### 2026-07-01：segment_ops + get_segment_op
- `UserOpManage.segment_ops: HashMap<i32, SegmentOp>`（userop.hh:347）+ `get_segment_op(space_idx)`。

### 2026-07-01（续）：CALLOTHER 注册 API
BUILTIN 常量对齐 userop.cc:30-35。register_builtin_by_id/register_string_copy_op/register_string_store_op + builtin_map + get_call_other_name。4 新测试。

### 2026-07-01（续 2）：SegmentOp::execute + supports_far_pointer
SegmentOp::execute（userop.cc:218-223）：2输入(base,inner)→(base<<4)+inner；1输入→inner。supports_far_pointer 字段 + has_far_pointer_support()。
<!-- annotation-pass: 2026-07-04 -->

# 2026-08-16：UserOpManage decode 链（CSPEC-UNIVERSAL-CHILD-0001）

- `UserPcodeOp` 摊平 `InjectedUserOp::injectid`（-1 非 injected）。
- `SegmentOp` 补 Ghidra 字段：`space_id`（spc）、`baseinsize`/`innerinsize`、
  `constresolve: Option<VarnodeData>`、`inject_id`。
- `UserOpManage` 补 `jump_assist_ops` 与 decode 链：
  `register_user_op`（userop.cc:490：同名异 index `Conflicting indices`、
  同 index 异名 `User op X has same index as Y`、segmentop 同空间
  `Multiple segmentops defined for same space`）、
  `decode_call_other_fixup`（cc:589+cc:85：decodeInject 先注册库 payload、
  再查 Unspecialized userop，错误 `Unknown userop name in <callotherfixup>`/
  `<callotherfixup> overloads userop with another purpose`）、
  `decode_segment_op`（cc:533+cc:225）、`decode_jump_assist`（cc:606+cc:302）、
  `decode_volatile`（cc:551：inputop/outputop 必填、functional→flags、
  重复注册错误逐字）、`read_varnode_attrs`（pcoderaw.cc:33）。
- `get_op(index)` 补 builtinmap 回落（userop.cc:408-415）。
对拍：unknown-target 编译后残留/segment 定制/volatile 双探针 MATCH；
segmentop/jumpassist 已移植无 oracle 观察（UNTESTED）。模块保持 L2。
