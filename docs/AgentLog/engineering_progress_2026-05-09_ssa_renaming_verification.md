# Engineering Progress Log: SSA Renaming Verification

## Objective
完成 SSA renaming 验证，验证 Heritage 模块的 SSA 重命名算法在各种 CFG 拓扑下的正确性。

## Actions Taken

1. **修复 `rename_direct` AddressSpace 碰撞 bug**:
   - `heritage.rs` 中 `rename_direct` 和 `visit_rename_direct` 使用 `BTreeMap<Address, ...>` 作为 renaming stack 的 key
   - 与 `place_multiequals_direct` 已修复使用 `(AddressSpace, Address)` 复合键不一致
   - 修复方式：将 stack key 从 `Address` 改为 `(AddressSpace, Address)`，涵盖 `rename_direct`、`visit_rename`、`visit_rename_direct` 三个方法
   - 证据来源：`src/heritage.rs` lines 386-524

2. **新增 4 项 SSA renaming 验证测试** (`funcdata.rs`):

   a. `test_ssa_rename_single_block_linear`:
      - 序列：`mov rax, rdi; add rax, rsi; ret`
      - 验证：op1 的 RAX 输入被重写为 op0 的输出 Varnode（`Arc::ptr_eq` 验证）
      - 验证：op0 和 op1 的 RAX 输出是不同的 Varnode 实例（不同 create_index）

   b. `test_ssa_rename_multi_block_phi_inputs`:
      - 使用与 `test_ssa_dual_block_phi_alignment` 相同的机器码（cmp/je/mov rax,1/jmp/mov rax,2/jmp/add rax,rsi/ret）
      - 验证：Phi 输入从前驱块定义正确填充（非占位符）
      - 验证：两个 Phi 输入是不同的 Varnode 实例
      - 验证：merge 块的 INT_ADD 使用 Phi 输出作为 RAX 输入

   c. `test_ssa_rename_diamond_pattern`:
      - 菱形 CFG：entry → {then: mov rax, 0x10 | else: mov rax, 0x20} → merge(ret)
      - 验证：merge 块有 RAX 的 Phi 节点
      - 验证：Phi 的两个输入分别来自不同分支的定义
      - 验证：Phi 输出与两个输入均不同

   d. `test_ssa_rename_input_varnode_for_undefined_read`:
      - 序列：`add rax, rsi; ret`（RAX 在使用前未定义）
      - 验证：输入 RAX 和输出 RAX 是不同的 SSA 版本

## Key Technical Details
- SSA 版本在 Rugra 中通过不同的 `Arc<RwLock<Varnode>>` 实例区分（每个实例有唯一的 `create_index`），使用 `Arc::ptr_eq` 进行身份验证
- `Varnode::version()` 当前返回硬编码 0，实际的 SSA 版本区分通过 `create_index` 和指针身份实现

## Test Results
- 全部 157 测试通过（原 153 + 新增 4），0 失败，0 回归

## Next Steps
- SSA renaming 跨图验证（需要真实 Ghidra 参考数据接入）
- 将 `Varnode::version()` 与实际 SSA 版本号关联（当前为占位实现）

## Review Status
- **Confidence**: Medium-High
- 按当前仓库可见信息判断，SSA renaming 在测试覆盖的 CFG 模式下行为正确
- 尚不能确认与 Ghidra 的 renaming 结果完全一致（需要 Ghidra 参考数据）
