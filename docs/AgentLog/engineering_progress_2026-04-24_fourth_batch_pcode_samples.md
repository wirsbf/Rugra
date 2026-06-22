# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-04-24（晚）  
**摘要 / Topic:** 第四批 P-code 对拍样本：and/or/xor/shl/shr/cmp  
**关联任务 / Related Tasks:** `docs/TODO_BOARD.md` 中关于最小 P-code 对拍链路推进

---

## 📝 本次核心变更

### 1. 新增 6 条最小对拍样本测试

| 指令 | 机器码 | 生成 P-code | 测试名 |
|------|--------|-------------|--------|
| `and rax, 0xf` | `48 83 e0 0f` | INT_AND + COPY (2 ops) | `test_and_rax_imm_minimal_alignment_path` |
| `or rax, 0x10` | `48 83 c8 10` | INT_OR + COPY (2 ops) | `test_or_rax_imm_minimal_alignment_path` |
| `xor rax, 0x7` | `48 83 f0 07` | INT_XOR + COPY (2 ops) | `test_xor_rax_imm_minimal_alignment_path` |
| `shl rax, 4` | `48 c1 e0 04` | INT_LEFT + COPY (2 ops) | `test_shl_rax_imm_minimal_alignment_path` |
| `shr rax, 4` | `48 c1 e8 04` | INT_RIGHT + COPY (2 ops) | `test_shr_rax_imm_minimal_alignment_path` |
| `cmp rax, rbx` | `48 39 d8` | INT_EQUAL(ZF) + INT_LESS(CF) + INT_SLESS(SF) (3 ops) | `test_cmp_rax_rbx_minimal_alignment_path` |

每条测试完整覆盖：反汇编 → lifting → opcode/output/input 结构验证 → Funcdata 注入 → verify_pcode_generation 通过。

### 2. 修复多线程测试竞争

所有 9 条对拍测试共享全局 `CURRENT_PROGRAM` mutex，在 `cargo test` 默认多线程模式下会出现竞争。

**修复:** 新增 `FFI_TEST_LOCK: Mutex<()>` 序列化锁，所有使用 `ffi::set_current_program()` 的测试在开始时获取锁。

### 3. 对拍样本覆盖总结

| 批次 | 指令 | 状态 |
|------|------|------|
| 第一批 | `mov rbx, rax` | ✅ |
| 第二批 | `add rax, 1` | ✅ |
| 第三批 | `sub rax, 8` | ✅ |
| 第四批 | `and rax, 0xf` | ✅ |
| 第四批 | `or rax, 0x10` | ✅ |
| 第四批 | `xor rax, 0x7` | ✅ |
| 第四批 | `shl rax, 4` | ✅ |
| 第四批 | `shr rax, 4` | ✅ |
| 第四批 | `cmp rax, rbx` | ✅ |

共 **9 条** 最小指令样本全部通过。

---

## 🔧 变更文件清单

| 文件 | 变更说明 |
|------|----------|
| `src/funcdata.rs` | 新增 6 条对拍测试；新增 FFI_TEST_LOCK 序列化锁；9 条测试全加锁 |

---

## 测试结果

**144 passed; 0 failed** — 全部测试通过（多线程模式）
