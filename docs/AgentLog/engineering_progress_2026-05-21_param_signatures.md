# Engineering Progress: Parameter Signature Database & Constant Display

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 深夜
- **核心意图**: 为 CALL ops 引入函数签名数据库以限制参数数量，改进常量显示格式，清除二进制特定的作弊代码
- **触及模块**: `src/coreaction.rs`, `src/printc.rs`

## 1. 代码变更与迭代 (Progress & Code Changes)

### coreaction.rs: ActionCallParams 函数签名数据库

1. **`known_param_count()` 函数**: 新增标准 libc 类型库，将函数名映射到已知参数数量。覆盖约 80 个常见 C/libc 函数（malloc, free, strlen, printf, fprintf, memcpy, memmove, socket, connect, read, write 等）以及 curl 相关函数（curl_easy_init, curl_easy_setopt, curl_easy_perform 等）。未知函数默认为 6（SysV AMD64 全部参数寄存器）。

2. **参数数量限制**: CALL ops 现在依据 `known_param_count()` 返回的签名信息进行参数裁剪：
   - 0 参数函数（如 `curl_version`, `__ctype_b_loc`）不附加任何参数
   - 1 参数函数（如 `malloc`, `free`, `strlen`）只附加 1 个参数
   - 已知 N 参数函数精确附加 N 个参数

3. **间隙处理改进**: 参数收集策略从"遇到第一个间隙即停止"改为"收集到最后一个找到的参数为止，中间间隙插入占位 Register varnode"。这避免了因寄存器活跃度分析不完整而丢失后续参数的情况。

### printc.rs: 常量显示改进

1. **十进制注释**: 常量值 >= 256 时，显示格式从纯十六进制改为带注释的格式：`0x2726 /* 10022 */`。小常量仍然只显示十六进制。

2. **负数检测**: 高位置位的常量（>= `0x8000_0000_0000_0000`）现在显示为有符号形式（如 `-1`）。`0xffffffff` 也特殊处理显示为 `-1`。

### 作弊代码清除

删除了以下二进制特定的硬编码映射函数：
- `curlopt_name()` — 硬编码 curl 选项常量名
- `known_global_name()` — 硬编码全局符号名
- `curl_setopt_arg_index` — 硬编码 curl_easy_setopt 参数索引

这些函数违反了通用反编译器的设计原则（不应该有针对特定二进制的硬编码知识），且实际效果不佳。用通用的 `known_param_count()` 函数签名数据库替代。

## 2. 架构推进与一致性审计 (Architecture & Alignment Audit)

- **文档同步确认**: 本次更新 `TODO_BOARD.md`（最近完成）、`CURRENT_STATUS.md`（反编译质量段落）。
- **测试状态**: 全部 168 测试通过，0 失败，0 回归。
- **Ghidra 对齐影响**: 函数签名数据库是向 Ghidra 的 `FunctionDefinitionDataType` / `DataTypeManager` 靠拢的第一步。Ghidra 使用完整类型库（.gdt / .fidb）进行函数签名恢复，当前 Rugra 的 `known_param_count()` 是一个轻量级近似，后续可以扩展为完整的函数原型数据库。

## 3. 下一步干涉计划 (Next Steps / Blockers)

1. **函数原型扩展**: `known_param_count()` 目前只返回参数数量，不包含参数类型信息。后续可以扩展为返回完整的 `FuncProto`（包含参数类型和返回类型）。
2. **类型库加载**: 考虑从外部文件（如 JSON 或 Ghidra .gdt 导出）加载函数签名，而非硬编码。
3. **常量显示进一步改进**: 可以考虑对已知枚举类型的常量显示符号名（如 `CURLOPT_URL` 而非 `0x2712`），但这需要类型信息支持。
4. **间隙处理验证**: 占位 Register varnode 的间隙填充策略需要在更多真实二进制上验证其正确性。
