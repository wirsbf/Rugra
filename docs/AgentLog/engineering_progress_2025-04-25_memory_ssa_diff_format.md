# Engineering Progress — 2025-04-25: Memory Instructions + SSA + Fine-Grained Diff + Ghidra Format

## 目标

推进 Rugra 验证框架的四个方向：
1. 内存操作指令（LOAD/STORE）对拍
2. SSA 对拍初步验证
3. Ghidra 参考侧快照格式设计
4. 函数级批量 Runner 细粒度差异

## 已完成工作

### 1. LOAD/STORE 内存指令对拍（+4 tests）

新增 4 条 LOAD/STORE 对拍测试，全部通过：

| Sample | 指令 | 机器码 | P-code 模式 | 状态 |
|--------|------|--------|-------------|------|
| F | `mov rax, [rbx]` | 48 8b 03 | LOAD + COPY | ✅ |
| G | `mov [rbx], rax` | 48 89 03 | STORE | ✅ |
| F2 | `mov rax, [rbx+0x10]` | 48 8b 43 10 | INT_ADD + LOAD + COPY | ✅ |
| G2 | `add [rbx], rax` | 48 01 03 | LOAD + INT_ADD + STORE | ✅ |

验证要点：
- LOAD 的 input[0] 是 RAM space ID 常量（value=2）
- STORE 无 output，有 3 个 input（space ID + 地址 + 值）
- 带位移的内存操作正确生成地址计算链（INT_ADD）
- 读-修改-写模式正确生成 LOAD + 运算 + STORE 三步序列

### 2. SSA 单块线性对拍（+1 test）

新增 SSA 对拍测试，验证 heritage 在单块函数上的行为：
- 单块无 MULTIEQUAL（Phi）节点 ✅
- Heritage pass 计数器正确递增 ✅

**重要发现**：`heritage()` 方法存在 deadlock 风险。该方法内部通过
`fd_weak.upgrade()` 重新获取 `Funcdata` 的写锁，如果调用者已持有写锁
则会死锁。解决方案：测试中直接调用 `place_multiequals_direct()` 和
`rename_direct()` 这两个不需要锁的 `_direct` 变体。

### 3. 细粒度 Diff 函数

重构了 `function_snapshot.rs` 中的 `collect_snapshot_mismatches()`：

**之前**：P-code/CFG/SSA 层差异只报告"是否不同"
**之后**：细化到具体字段级别

新增 3 个 diff 函数：
- `diff_pcode_ops()` — 逐 op 比较 opcode + output + inputs（含 slot 级别）
- `diff_cfg_blocks()` — 逐 block 比较 start address + successors + predecessors + ops
- `diff_ssa_varnodes()` — 逐 varnode 比较 space + offset + version + def/use chains

所有 8 个原有 snapshot 测试在新逻辑下仍通过。

### 4. Ghidra 快照格式设计

新增文档：
- `docs/method/ghidra_snapshot_format.md` — 完整的 JSON schema 规范
  - AddressSpace 映射表
  - OpCode 映射表
  - Unique space 偏移处理约定
  - Ghidra Python 导出脚本示例
  - Rugra 侧导入 API 使用说明
- `docs/method/impl/ghidra_export_example.json` — 手工构造的示例 JSON

## 测试结果

```
test result: ok. 152 passed; 0 failed; 0 ignored; 0 measured
```

相比上次会话（147 tests），新增 5 个测试（4 LOAD/STORE + 1 SSA）。

## 修改文件清单

| 文件 | 变更类型 |
|------|----------|
| `src/funcdata.rs` | MODIFY — 新增 5 个测试 |
| `src/align/function_snapshot.rs` | MODIFY — 重构 diff 逻辑 |
| `docs/method/ghidra_snapshot_format.md` | NEW |
| `docs/method/impl/ghidra_export_example.json` | NEW |

## 遗留事项

1. **SSA Test B（双块 Phi）**：dominator tree 计算已就绪（`build_dom_tree()` 实现完整），
   但尚未编写双块测试。需要手工构造一个有 Phi 节点的场景。
2. **heritage() deadlock**：建议在 `Funcdata` 上提供一个不需要 `Arc<RwLock>` 的
   `run_heritage_direct()` 便捷方法，避免使用者踩坑。
3. **JSON 导入测试**：示例 JSON 已创建，但尚未在代码中添加自动化的导入+比较测试。
4. **Ghidra 侧实际导出**：需要真实 Ghidra 环境才能验证导出脚本。
