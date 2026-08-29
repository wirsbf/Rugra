# x86_lift.rs API Reference

2026-06-27: opcode 改名对齐 Ghidra 规范名 (INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE / BOOL_NOT->BOOL_NEGATE)，纯重命名，行为不变。

2026-06-29: CALL op 建立 RAX 返回值 output（Register@0x0 size 8）。对齐 Ghidra `ActionFuncLink::funcLinkOutput`（coreaction.cc:1551 `newVarnodeOut`）：为未锁定 prototype 的 CALL 分配返回值寄存器作为 output，使返回值进入 SSA def 链。此前 CALL output 永远为 None，导致返回值"丢失"——下游使用（如 `__dest = strdup(buf)`）变成"声明却未赋值"。多寄存器/XMM 返回与 assumedOutputExtension 是后续工作。

2026-06-29（完整移植）：lifter 精简——CALL op 现在只挂目标地址 inrefs[0]（对齐 Ghidra x86 lifter ia.sinc）。移除了此前 lifter 硬塞的 6 个 SysV 参数寄存器 input + RAX output。参数和返回值现由 `ActionFuncLink::funcLinkInput/funcLinkOutput`（coreaction.cc:1474/1521）在分析层建立：funcLinkInput 对已知函数用 `opInsertInput(create_with_space(8, Register, reg_off))` 建参数 varnode，funcLinkOutput 用 `newVarnodeOut` 建 RAX 返回值。这是 Ghidra 四步链（lifter CALL → setupCallSpecs → funcLink → trial 恢复）的完整对齐。

### 2026-07-04：BRANCHIND 发射
- `jmp` 指令的非 Immediate 操作数（Register/Memory）现在正确发射 CPUI_BRANCHIND。
- Register 操作数：直接用寄存器 varnode 作为 BRANCHIND 目标。
- Memory 操作数：先 LOAD 再 BRANCHIND。
- 新增 `reg_offset` helper（复用 get_register 的映射表）。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-30：RIP/EIP 偏移修正(0x200 → 0x288)
- `get_register` 表中 `"rip" | "eip"` 的寄存器空间偏移由 0x200 改为 **0x288**。
- 依据:锁定 oracle `sleigh_specs/x86-64.sla` getAllRegisters 全量 dump
  (RIP=0x288:8 / EIP=0x288:4 / rflags=0x280 / CF=0x200..ID=0x214 各 1 字节;
  证据见 `examples/x86carry_probe.rs` 与
  `docs/alignment_docs/CARRY-PRINT-ROOTCAUSE-2026-08-30.md` §2.1)。
- 旧值 0x200 与 1-bit flags 区(CF..F5)别名:所有 rip 相对内存操作数的地址计算
  曾落在 flags 区 varnode 上。curl E2E 实测输出字节不变(3104/0/0)。
