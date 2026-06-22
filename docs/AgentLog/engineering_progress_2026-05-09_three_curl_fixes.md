# Engineering Progress Log: Three Curl Decompilation Fixes

## Objective
改进 curl 二进制反编译输出质量，解决三个关键问题：寄存器命名、循环检测、死代码消除。

## Actions Taken

### Problem 1: HighVariable 寄存器命名 (merge.rs)

- **问题**: 所有变量输出为 uVar0, uVar1 等无意义名称，无法辨认寄存器
- **修复**:
  - `merge.rs` 新增 `register_name(offset, size) -> Option<&str>` 函数：根据 Varnode 的 offset 和 size 查表返回 x86-64 寄存器名（RAX, EAX, AX, AL, AH, RDI, RSI 等）
  - `merge.rs` `assign_names()` 优先使用 `register_name` 为 Register 空间的 HighVariable 生成人类可读名称
- **效果**: curl 输出从 `uVar0 = uVar1 + uVar2` 改为 `RAX = RDI + RSI` 等真实寄存器名
- **限制**: Unique 空间临时变量仍输出 uVarNN（需要后续改进）

### Problem 2: CBRANCH-latch 循环检测 (blockaction.rs)

- **问题**: 真实二进制中的循环未被识别，输出为 goto 而非 do-while/while
- **修复**:
  - `blockaction.rs` 新增 `detect_cbranch_loops()` 函数
  - 检测以 CBRANCH 结尾的 latch 块回边模式（latch 块分支目标指向支配自身的 header 块）
  - 匹配到的模式包装为 `BlockWhileDo`（do-while 语义）
- **效果**: curl 反编译中成功检测出 do-while 循环

### Problem 3: ActionFinalStructure (blockaction.rs)

- **问题**: 无法结构化的控制流产生大量无意义 BRANCH/CBRANCH，且 BRANCH 后存在不可达死代码
- **修复**:
  - `op.rs` 新增 `GOTO` 常量（PcodeOp 操作码值 `72`）
  - `blockaction.rs` 新增 `tag_gotos()`：将无法折叠为 break/continue 且跳转目标非 fallthrough 的 BRANCH/CBRANCH 标记为 GOTO
  - `blockaction.rs` 新增 `remove_dead_code()`：清除 BRANCH 后同一基本块内的不可达代码
- **效果**: 输出更干净的 if-goto 模式，消除死代码

## Files Changed

| 文件 | 变更 |
|------|------|
| `src/merge.rs` | 新增 `register_name()` 函数 + `assign_names()` 使用寄存器名 |
| `src/op.rs` | 新增 `GOTO` 常量 |
| `src/blockaction.rs` | 新增 `detect_cbranch_loops()` + `tag_gotos()` + `remove_dead_code()` |

## Test Results
- 全部 161 测试通过，0 失败，0 回归
- 未新增测试（功能通过 curl_decompile example 验证）

## Curl 反编译改进总结

| 改进项 | Before | After |
|--------|--------|-------|
| 变量名 | uVar0, uVar1, ... | RAX, RDI, RSI, R8, ... |
| 循环 | 全部为 goto | 检测出 do-while 循环 |
| 死代码 | BRANCH 后存在不可达代码 | 已清除 |
| goto 模式 | 混乱的 BRANCH/CBRANCH | 更干净的 if-goto |

## 已知遗留问题

- Unique 空间临时变量仍输出 uVarNN（需命名策略改进）
- 许多 goto 仍然保留，因为对应的控制流确实是非结构化的
- 类型系统仍然薄弱，多数变量类型为 int
- switch-case 结构尚未支持

## Next Steps
- Unique 空间临时变量命名改进
- switch-case 检测（BlockSwitch + jump table）
- 类型恢复与函数签名推断
- HighVariable 集成到更完整的 codegen 流程

## Review Status
- **Confidence**: Medium
- 三项修复均通过 curl_decompile example 验证，输出质量明显改善
- register_name 仅覆盖常见 x86-64 寄存器，可能遗漏部分特殊寄存器
- 循环检测仅覆盖 CBRANCH-latch 模式，while/for 等需要后续补充
- ActionFinalStructure 为初步实现，与 Ghidra 完整的 finalstructure pass 仍有差距
