# x86_lift.rs API Reference

2026-06-27: opcode 改名对齐 Ghidra 规范名 (INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE / BOOL_NOT->BOOL_NEGATE)，纯重命名，行为不变。

2026-06-29: CALL op 建立 RAX 返回值 output（Register@0x0 size 8）。对齐 Ghidra `ActionFuncLink::funcLinkOutput`（coreaction.cc:1551 `newVarnodeOut`）：为未锁定 prototype 的 CALL 分配返回值寄存器作为 output，使返回值进入 SSA def 链。此前 CALL output 永远为 None，导致返回值"丢失"——下游使用（如 `__dest = strdup(buf)`）变成"声明却未赋值"。多寄存器/XMM 返回与 assumedOutputExtension 是后续工作。

2026-06-29（完整移植）：lifter 精简——CALL op 现在只挂目标地址 inrefs[0]（对齐 Ghidra x86 lifter ia.sinc）。移除了此前 lifter 硬塞的 6 个 SysV 参数寄存器 input + RAX output。参数和返回值现由 `ActionFuncLink::funcLinkInput/funcLinkOutput`（coreaction.cc:1474/1521）在分析层建立：funcLinkInput 对已知函数用 `opInsertInput(create_with_space(8, Register, reg_off))` 建参数 varnode，funcLinkOutput 用 `newVarnodeOut` 建 RAX 返回值。这是 Ghidra 四步链（lifter CALL → setupCallSpecs → funcLink → trial 恢复）的完整对齐。
