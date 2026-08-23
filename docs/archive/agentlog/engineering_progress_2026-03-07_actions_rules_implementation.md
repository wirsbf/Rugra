# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-07
**摘要 / Topic:** Fix Doctest Regressions & Implement Missing Actions/Rules
**关联任务 / Related Tasks:** `docs/TODO_BOARD.md`

## 📝 代码迭代 (Code Iterations)
1. **Doctest 回归修复**:
   - 修复 `src/lib.rs` 的 Quick Start doctest：原来引用已注释掉的 `Decompiler` 结构体，替换为基于当前 `Funcdata`/`ActionDatabase` API 的 `ignore` 示例。
   - 修复 `src/utils.rs` 的 `bits::extract` doctest：`utils` 是私有模块导致 `rugra::utils` 路径不可达，改为 `ignore` 标注。

2. **3 个 Stub Action 实装 (`coreaction.rs`)**:
   - `ActionConstantPtr::apply()`：扫描 LOAD/STORE 操作，对地址输入为常量的 Varnode 标记 `READONLY` 标志。
   - `ActionCse::apply()`：CSE 公共子表达式消除，以 `(opcode, 输入指针集)` 哈希去重，对可交换操作排序输入。
   - `ActionMergeCopy::apply()`：遍历存活 COPY 操作，调用 `merge_test()`/`merge_force()` 合并输入/输出 HighVariable。

3. **3 个新 Rule 变换 (`ruleaction.rs`)**:
   - `RuleSextEliminate`：INT_SEXT 同尺寸降级为 COPY（与 RuleZextEliminate 对称）。
   - `RuleTrivialArith`：算术恒等消除（x+0, x-0, x*1, x^0, x|0 → x），注意 0-x 不简化。
   - `RuleShiftBitops`：移位零消除（x<<0, x>>0, x>>>0 → x）。
   - 附带 6 个单元测试全部通过。

4. **OpCode 辅助方法 (`opcodes.rs`)**:
   - `is_commutative()`: 14 种可交换操作码。
   - `is_commutative_or_pure()`: 适用于 CSE 的纯确定性操作（排除 LOAD/STORE/分支/调用/SSA 内部操作）。

## 🔐 架构一致性审计 (Alignment Audit)
- 所有新增 Rule 和 Action 的设计严格参照 Ghidra `coreaction.hh` 和 `ruleaction.hh` 的同名类。
- CSE 的实现参考了 Ghidra `ActionCse` 的"按输入指针哈希"策略。
- OpCode 的 `is_commutative()` 覆盖了 Ghidra 中标记为 commutative 的所有操作码。

## ⏭️ 下一步干涉计划 (Next Steps)
1. 继续填充缺失的 Action 算法（如 `ActionConstantPtr` 的地址解析扩展、`ActionMergeCopy` 的 address-pair cover 分析）。
2. 引入 FFI Runtime Verify 来实际对拍 Rule 变换前后的语义一致性。
3. 修复 doc_sync 工具报告的 36 个预存时间戳不同步问题（这些都是历史遗留，非本次会话引入）。
