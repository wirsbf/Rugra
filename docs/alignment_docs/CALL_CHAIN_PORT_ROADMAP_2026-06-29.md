# CALL 参数/返回值建立链完整移植路线图

**日期**: 2026-06-29
**目标**: 完整移植 Ghidra 的 CALL 参数/返回值建立链（不简化），消除 curl my_fwrite 的 CALL 参数错误 + 返回值丢失

## Ghidra ground truth（四步链）

1. **lifter**：CALL op 只有目标地址 inrefs[0]，无参数、无 output
2. **FlowInfo::setupCallSpecs**（flow.cc:680）：控制流分析时为每个 CALL 建 FuncCallSpecs，存 qlst
3. **ActionFuncLink::apply**（coreaction.cc:1575）：遍历 qlst，funcLinkInput + funcLinkOutput
   - funcLinkInput（coreaction.cc:1474）：已知→opInsertInput(newVarnode)；未知→initActiveInput
   - funcLinkOutput（coreaction.cc:1521）：已知→newVarnodeOut；未知→initActiveOutput
4. **ActionActiveParam/ActionReturnRecovery/ActionInputPrototype/ActionOutputPrototype**：trial 恢复链

## 已完成（已提交）

| commit | 内容 | 状态 |
|---|---|---|
| 2807ca1 | lifter 给 CALL 建 RAX output（临时简化，待步骤1移除） | ✅ |
| 6908a9e | ProtoModel::default_x86_64 SysV offset 修正（RDI=0x38等） | ✅ |
| d8aa99a | ensure_callspecs 生产路径建 FuncCallSpecs + ActionFuncLink 接入管线（Heritage 前） | ✅ |

**当前状态**：FuncCallSpecs 在生产路径建立，ActionFuncLink 接入管线。但 funcLinkInput/funcLinkOutput 仍是简化版（initActiveInput/Output，无 opInsertInput/newVarnode）。CALL 参数仍由 lifter 挂寄存器 + ActionCallParams trim。

## 待完成步骤

### 步骤 3：funcLinkInput 完整 opInsertInput/newVarnode
- **现状**：func_link_input（coreaction.rs:3893）只 init_active_input + 注册 trial，不建 varnode（注释"deferred"）
- **要做**：
  - 签名改为 `func_link_input(fc: &mut FuncCallSpecs, fd: &mut Funcdata, op: &PcodeOpRef)`
  - 对已知函数（libc 表 known_param_count/types）：查参数个数 + 地址，`fd.op_insert_input(op, fd.new_varnode(size, addr), slot)`
  - 对未知函数：保持 initActiveInput（trial 恢复由 ActionActiveParam 处理）
- **借用处理**：apply 里先收集 (op_ref, callspec_index) 对，避免 fd 双重借用
- **对齐**：coreaction.cc:1508 `opInsertInput(op, newVarnode(size, addr), numInput)`

### 步骤 4：funcLinkOutput 完整 newVarnodeOut
- **现状**：func_link_output（coreaction.rs:3922）locked 分支空体
- **要做**：
  - 已知返回类型→`fd.new_varnode_out(size, addr, op)` + assumedOutputExtension（建 INT_SEXT/INT_ZEXT）
  - 未知→initActiveOutput
- **对齐**：coreaction.cc:1551 `newVarnodeOut(sz, addr, callop)`

### 步骤 1+5：lifter 精简 + 移除 ActionCallParams（必须与步骤3/4紧凑衔接）
- **lifter**（x86_lift.rs:545-558）：移除 6 个寄存器 input + RAX output（CALL 只留 target inrefs[0]）
- **管线**（action.rs）：
  - 移除 ActionCallParams（coreaction.rs:956，被 funcLinkInput 取代）
  - ActionInferParams 保留（它填 fd.funcp.parameters，推本函数参数）
  - 接入 ActionActiveParam / ActionReturnRecovery / ActionInputPrototype / ActionOutputPrototype
- **顺序对齐**：Ghidra FuncLink(5484)→Heritage(5492)→ActiveParam(5499)→ReturnRecovery(5500)
- **风险**：步骤 1 移除 lifter 挂寄存器后，步骤 3 的 funcLinkInput 必须已完成建参数，否则 CALL 参数全空。**步骤 3、4、1、5 必须在同批改动完成**

### 步骤 6：ActionReturnRecovery 完整化
- **现状**：coreaction.rs:4438，骨架（无 buildReturnOutput / ancestorOpUse / deriveOutputMap）
- **要做**：
  - 补 AncestorRealistic + ancestorOpUse（判定返回值 varnode 真实可达）
  - 补 buildReturnOutput（coreaction.cc:1836）：把恢复的返回值挂成 CALL output
  - 补 deriveOutputMap
- **对齐**：coreaction.cc:1908-1955

### 步骤 7：ActionActiveParam 完整化
- **现状**：coreaction.rs:3370，部分（缺 AliasChecker.gather / finalInputCheck / buildInputFromTrials 调用）
- **要做**：
  - 补 AliasChecker.gather（栈别名分析）
  - 补 finalInputCheck + buildInputFromTrials + trimmable
- **对齐**：coreaction.cc:1725-1771

### 步骤 8：验证 + 文档同步
- debug_my_fwrite：fwrite/fopen 参数 + 返回值正确
- curl/httpd 审计
- 780 测试
- 更新 fspec.md / coreaction.md / x86_lift.md

## 关键设计决策（已定）

- **保留 CALL inrefs[0] 为目标地址**（不改 FSPEC 空间）。用 callspecs + op_addr 索引等效 Ghidra getCallSpecs(op)
- **libc 签名表（known_param_count/types）移到 funcLinkInput**，作为"已知 prototype"驱动 locked 路径
- **ActionInferParams 保留**（它推本函数参数，Ghidra ActionInputPrototype 等价）

## 不做的事

- 不改成 FSPEC 空间
- 不保留 ActionCallParams 的硬编码 SysV trim（被 funcLinkInput 取代）

## 关键代码位置

| 文件 | 位置 | 内容 |
|---|---|---|
| src/coreaction.rs:3825 | ActionFuncLink impl | ensure_callspecs + func_link_input/output |
| src/coreaction.rs:956 | ActionCallParams | 待移除（步骤5） |
| src/coreaction.rs:1197 | ActionInferParams | 保留（本函数参数） |
| src/coreaction.rs:3370/4438 | ActionActiveParam/ReturnRecovery | 待完整化（步骤6/7） |
| src/disasm/x86_lift.rs:545 | lifter CALL arg regs | 待移除（步骤1） |
| src/action.rs:386 | decompile_group 管线 | 待调整顺序（步骤5） |
| src/funcdata.rs:302/316/484 | op_set_input/op_insert_input/new_varnode_out | 已有，funcLinkInput/Output 用 |
| src/fspec.rs:218 | FuncCallSpecs | 结构完整，待 op 引用字段（步骤3借用） |
