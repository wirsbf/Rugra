# x86_lift.rs API Reference

2026-06-27: opcode 改名对齐 Ghidra 规范名 (INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE / BOOL_NOT->BOOL_NEGATE)，纯重命名，行为不变。

2026-06-29: CALL op 建立 RAX 返回值 output（Register@0x0 size 8）。对齐 Ghidra `ActionFuncLink::funcLinkOutput`（coreaction.cc:1551 `newVarnodeOut`）：为未锁定 prototype 的 CALL 分配返回值寄存器作为 output，使返回值进入 SSA def 链。此前 CALL output 永远为 None，导致返回值"丢失"——下游使用（如 `__dest = strdup(buf)`）变成"声明却未赋值"。多寄存器/XMM 返回与 assumedOutputExtension 是后续工作。
