# Engineering Progress: Type-Aware Cast Emission in PrintC

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 01:15
- **核心意图**: 将迭代类型推断引擎（ActionTypeInfer）与 C 代码发射器（PrintC）对接，实现类型转换的自动插入，提升反编译输出的类型准确度。
- **触及模块**: `src/printc.rs`, `src/funcdata.rs`, `src/ruleaction.rs`, `docs/api/coreaction.md`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

### PrintC 类型转换集成
- **CastStrategyC 集成**: 在 [src/printc.rs](file:///d:/ghidra/rugra/src/printc.rs) 的 `PrintC` 结构体新增 `cast_strategy: CastStrategyC` 字段（`promote_size = 4`），为后续类型判定提供基础设施。
- **LOAD 类型转换打印**: `op_load` 和 `emit_inline_expr` 中的 LOAD 分支现在检查地址输入的 `v_type`。若为指针类型，发射 `*(type *) addr` 格式而非无类型的 `*addr`。
- **STORE 类型转换打印**: `op_store` 中的非内联地址路径同样检查指针类型，实现与 LOAD 对称的类型感知输出。
- **ZEXT/SEXT 类型感知 cast**: 在 `op_unary` 和 `emit_inline_expr` 中，`CPUI_INT_ZEXT` 和 `CPUI_INT_SEXT` 现在检查输出 varnode 的 `v_type`，若有明确类型则使用该类型名（如 `(long)`）而非硬编码的 `(uint)` / `(int)`。

### 关键 bug 修复
- **RwLock 死锁修复**: 修复了 [src/funcdata.rs](file:///d:/ghidra/rugra/src/funcdata.rs) 中 `test_type_propagation` 的变量链接循环。原代码在持有 `op_ref.0` 的 write lock 时尝试遍历 `fd.obank.alivelist` 获取其他 op 的 read lock，当同一 op 被遍历时导致死锁。重构为预先收集所有 output varnode 信息后再进行链接。

### 清理
- **未使用导入移除**: 移除了 `src/ruleaction.rs` 中未使用的 `use crate::varnode::Varnode;` 导入。
- **API 文档同步**: 更新了 [docs/api/coreaction.md](file:///d:/ghidra/rugra/docs/api/coreaction.md)，将 `ActionTypeInfer` 的描述从过时的单趟推断升级为完整的五规则迭代固定点引擎文档。

---

## 2. 架构推进与一致性审计 (Architecture & Alignment Audit)
- **单元测试验证**: 全部 163 个单元测试通过，0 失败，0 编译警告。
- **与 Ghidra 对齐情况**: PrintC 的 cast 发射对齐了 Ghidra `PrintC` 中 `push_typecast` 的核心概念，但尚未实现完整的 `CastStrategy::is_cast_implied` 判定流（当前仅在 LOAD/STORE/ZEXT/SEXT 等关键点插入 cast，尚未在通用赋值路径中做全局 cast 判定）。

---

## 3. 下一步干涉计划 (Next Steps / Blockers)
- 新增 `test_type_cast_emission` 单元测试，验证 PrintC 在有类型信息时的 cast 输出。
- 探索通用赋值路径中的 cast 判定（利用 `CastStrategyC::is_cast_implied`）。
- 结构体（Struct）成员和偏移量的类型传播恢复方案。
