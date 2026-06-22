# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-04-24（深夜）  
**摘要 / Topic:** 多指令序列对拍：单块+多块  
**关联任务 / Related Tasks:** 从单条指令升级到多指令序列对拍

---

## 📝 本次核心变更

### 新增 3 条多指令序列对拍测试

| 测试名 | 指令序列 | P-code ops | 基本块数 | 验证重点 |
|--------|----------|-----------|---------|----------|
| `test_seq_mov_add_ret` | `mov rax,rdi; add rax,rsi; ret` | 4 | 1 | 多指令 lift 合并 + Funcdata 注入 |
| `test_seq_mov_and_shl_ret` | `mov rax,rdi; and rax,0xf; shl rax,4; ret` | 6 | 1 | 算术链路 3 段运算 |
| `test_seq_cmp_je_multiblock` | `cmp rdi,rsi; je +8; mov rax,1; ret; xor rax,rax; ret` | 9 | 3 | **CBRANCH 分支 + 多基本块构建** |

### 关键里程碑

**`test_seq_cmp_je_multiblock` 是第一个验证条件分支+多基本块分割的测试**，证明了：
- `cmp` 正确生成 3 个 flag-setting ops（ZF/CF/SF）
- `je` 正确生成 CBRANCH 并携带目标地址
- `inject_raw_ops` 正确识别 CBRANCH 和 RETURN 作为 block terminator
- 最终生成 3 个基本块，每个块的 op 数量正确

---

## 对拍覆盖进度汇总

| 类型 | 样本数 | 状态 |
|------|--------|------|
| 单指令（mov/add/sub/and/or/xor/shl/shr/cmp） | 9 | ✅ |
| 多指令单块（mov+add+ret, mov+and+shl+ret） | 2 | ✅ |
| 多指令多块（cmp+je+两路分支） | 1 | ✅ |
| **总计** | **12** | **147 tests passed** |

---

## 测试结果

**147 passed; 0 failed** — 多线程模式全量通过
