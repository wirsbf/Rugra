# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-04-24  
**摘要 / Topic:** 修复 P-code 对拍阻塞项 + 新增第三条最小样本  
**关联任务 / Related Tasks:** `docs/TODO_BOARD.md` 中关于最小 P-code 对拍链路推进

---

## 📝 本次核心变更

### 1. 修复 `add rax, 1` 对拍失败（悬了 40+ 天的阻塞项）

根因分析后发现有 **三个独立的 bug**：

#### Bug 1: 参考 opcode 来源错误
`runtime_verify.rs::verify_pcode_generation` 使用 `r_op.get_opcode() as i32` 作为 "Ghidra 参考 opcode"。但 Rugra 和 Ghidra 的 OpCode 枚举值**完全不同**：
- Rugra: `CPUI_INT_ADD = 4`, `CPUI_BRANCH = 49`
- Ghidra: `CPUI_INT_ADD = 19`, `CPUI_BRANCH = 4`

**修复:** 新增 `ffi::to_ghidra_opcode()` 将 Rugra OpCode 正确转换为 Ghidra 整数编号。

#### Bug 2: unique 空间 offset 精确比较
unique varnode 的 offset 是临时分配的，Rugra 和 Ghidra 使用不同的分配策略，不应精确比较。

**修复:** 
- `align/varnode.rs::verify_varnode()`: unique 空间跳过 offset 比较
- `ffi.rs::rugra_compare_pcode()`: unique 空间跳过 offset 比较
- `runtime_verify.rs::verify_pcode_generation()`: unique 空间 VarnodeFFI 使用 sentinel offset

#### Bug 3: space_id FFI 映射不一致
`space.rs` 内部映射: Ram=0, Register=1, Unique=2, Const=3  
VarnodeFFI FFI 约定: Register=1, Ram=2, Unique=3, Const=4

`rugra_compare_pcode` 直接用 `space().space_id() as i32` 比较 FFI 传入的 space_id，导致 Const 空间不匹配。

**修复:** 新增 `ffi::space_to_ffi_id()` 统一内部到 FFI 的空间映射。

#### 额外修复
- `align/pcodeop.rs::verify_opcode()`: 使用 `ffi::map_ghidra_opcode()` 替代 `OpCode::from_i32()`
- `ffi::map_ghidra_opcode` 改为 `pub`

### 2. 新增第三条最小样本 `sub rax, 8`

新增 `funcdata::tests::test_sub_rax_imm_minimal_alignment_path`，完整覆盖：
- 反汇编 `0x48 0x83 0xe8 0x08`
- Lifting → INT_SUB + COPY
- 注入 Funcdata
- verify_pcode_generation 通过

### 3. 测试结果

**138 passed; 0 failed** — 全部测试通过，包含：
- `mov rbx, rax` — COPY 对拍 ✅
- `add rax, 1` — INT_ADD + COPY 对拍 ✅（本次修复）
- `sub rax, 8` — INT_SUB + COPY 对拍 ✅（本次新增）

---

## 🔧 变更文件清单

| 文件 | 变更说明 |
|------|----------|
| `src/ffi.rs` | 新增 `to_ghidra_opcode()`、`space_to_ffi_id()`；公开 `map_ghidra_opcode`；unique offset 跳过 |
| `src/align/runtime_verify.rs` | 使用 `to_ghidra_opcode()` 替代 `as i32`；unique sentinel offset |
| `src/align/pcodeop.rs` | `verify_opcode()` 使用 `map_ghidra_opcode` |
| `src/align/varnode.rs` | unique 空间跳过 offset 比较 |
| `src/funcdata.rs` | 新增 `test_sub_rax_imm_minimal_alignment_path` |
| `docs/TODO_BOARD.md` | 更新 P-code 对拍任务状态 |

---

## ⏭️ 下一步建议

1. 继续推进第四批指令样本：`and/or/xor`、`shl/shr`、`cmp/jcc`
2. 细化函数级批量 compare 的差异粒度
3. 设计 Ghidra 侧快照导出约定
4. 清理编译警告（~533 个）
