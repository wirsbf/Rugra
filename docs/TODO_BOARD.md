# Todo Board (任务看板)

本文档跟踪当前未竟的开发与对齐任务。每次会话结束时，务必更新此文档的状态。

## P0 紧急与核心任务 (Critical)
- [ ] **SSA 核心对齐详述**: 补全 `docs/alignment_docs/blueprints/ssa_phi_placement_rules.md` 中的技术细节，比对 `heritage.rs` 与 Ghidra `heritage.cc`。
- [ ] **旧管道迁移计划**: 制定计划将现有的 `src/analysis/*` 和 `src/pcode/program.rs` 迁移至基于 `Funcdata` + `Action` 的新并发反编译管线上。

## P1 高优推进 (High)
- [ ] **调用约定对齐详述**: 补全 `docs/alignment_docs/checklists/x86_64_calling_convention.md` 等相关 FFI 和参数传递规则。
- [ ] **类型恢复系统对齐**: 完善 `type_system` 和 `analysis::type_propagation` 中数据流强制转换与类型格子的推导规范。

## P2 常规迭代 (Medium)
- [ ] 重启 FFI 测试桩编排：目前有了 API 文档，可以更有效地编写基于 `rugra_compare_pcode` 的 C++ / Rust 端对拍测试。

## 已完成 (Completed in Recent Sessions)
- [x] **2026-03-07**: 全面废弃自动化 API 文档生成，手工完成 `docs/api/` 下所有 66 个源文件的 34 份高要求 API/架构参考文档。
- [x] **2026-03-07**: 初始化并规范化 `docs/alignment_docs/` 对齐追踪体系，设定了强制性的对齐文档模板。
- [x] **2026-03-06**: 实现 RustVSR 最新项目架构向导梳理至 `PROJECT_STRUCTURE.md`。
