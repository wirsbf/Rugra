# `subflow.rs` API Reference

**源代码路径**: `src/subflow.rs`
**Ghidra 对应**: `subflow.hh` / `subflow.cc` (4589行)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——SubvariableFlow 核心方法覆盖（含 do_trace/do_replacement/trace_forward/backward）。11 单元测试。

## 模块说明

子流分析：缩小携带较小逻辑值的大 Varnode。
对应 Ghidra 的 `subflow.hh`。

## 导出的公共 API

### `pub struct ReplaceVarnode`
持有较小逻辑值的 Varnode 占位符。对应 `SubvariableFlow::ReplaceVarnode`。

### `pub struct ReplaceOp`
操作较小逻辑值的 PcodeOp 占位符。对应 `SubvariableFlow::ReplaceOp`。

### `pub enum PatchType`
操作补丁类型（CopyPatch/ComparePatch/ParameterPatch/ExtensionPatch/PushPatch/Int2FloatPatch）。

### `pub struct PatchRecord`
需要修补但无流穿透的操作。对应 `SubvariableFlow::PatchRecord`。

### `pub struct SubvariableFlow`
子流分析引擎。对应 `SubvariableFlow`。
- `new(flow_size, aggressive, sext)` — 构造
- **当前限制**: traceForward/traceBackward/doReplacement 待补。

测试：subflow::tests 2 个。

## 2026-06-26（续）：subflow.rs 完善实现

新增 SubvariableFlow 分析方法：
- `set_replacement(vn, mask)` — 注册子变量覆盖（subflow.cc setReplacement）
- `has_replacement(vn)` / `get_replacement_index(vn)` — 查询
- `create_op(opc, num_params)` / `create_op_down(opc, num_params, op)` — 创建子图 op
- `add_push(op, rvn)` / `add_terminal_patch(op, rvn)` / `add_compare_patch(rvn1, rvn2, op)` — 添加补丁
- `is_worthwhile()` — 是否值得替换（pull_count >= 2）
- `check_mask(mask, flow_bits)` — 验证掩码是有效子变量

测试：新增 4 个（set_replacement + create_op + patches_and_worthwhile + check_mask）。
### 2026-06-27（会话3 L1）：subflow.cc 核心算法移植

移植 SubvariableFlow 的核心原语和分析入口：
- `does_or_set(op, mask)` — doesOrSet(subflow.cc:26-36)：INT_OR 是否设置掩码所有位为 1
- `does_and_clear(op, mask)` — doesAndClear(subflow.cc:43-53)：INT_AND 是否清除掩码所有位
- `compute_consume_mask(vn)` — Varnode getConsume 等价
- `do_trace(fd, seed, mask)` — doTrace(subflow.cc:1410-1434)：子变量流追踪入口（简化版：扫描引用种子的 op 计数 pull 点）

3 个新单元测试：does_or_set、does_and_clear、do_trace 空 Funcdata。

### 2026-06-27（会话3 L1续）：traceForward + traceBackward 完整移植

移植 SubvariableFlow 的核心双向数据流追踪算法：

- **trace_forward_single** — traceForward(subflow.cc:373-659, ~286行)：
  对每个 ReplaceVarnode 的后代 op 进行模式匹配：
  - COPY/MULTIEQUAL/INT_NOT/INT_XOR → 透传，创建平行 op
  - INT_OR → doesOrSet 检查截断；否则透传
  - INT_AND → 常量掩码提取 / doesAndClear 截断 / 否则透传
  - INT_ZEXT/INT_SEXT → COPY 透传
  - INT_ADD → 仅当掩码从 bit0 开始
  - INT_LEFT/INT_RIGHT/INT_SRIGHT → 常量位移，计算新掩码
  - SUBPIECE → 字节提取
  - 比较类 / 布尔类 / CALL / RETURN → pull 点
  - 未知 op → 中止该分支

- **trace_backward_single** — traceBackward(subflow.cc:665-861, ~196行)：
  从定义 op 反向追踪逻辑值：COPY/MULTIEQUAL/INT_NOT/INT_XOR/INT_AND/INT_OR/INT_ADD/SUBPIECE

do_trace 现使用 worklist 驱动 trace_forward_single，再调用 trace_backward_single。

### 2026-06-27（会话3 L1续）：doReplacement 替换执行引擎

移植 `SubvariableFlow::doReplacement`（subflow.cc:1435-1545）：
1. 处理 push patches：设置 push op 的 output 为逻辑值，创建 INT_ZEXT 占位
2. 创建子图新 ops：newOp + opSetOpcode + newUniqueOut + opInsertAfter
3. 处理 copy/compare/parameter/extension patches：修改现有 op 的输入/opcode

完整 SubvariableFlow 三段式现已就位：doTrace → traceForward/traceBackward → doReplacement。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
