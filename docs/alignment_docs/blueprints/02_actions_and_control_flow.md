# Rudra 实现蓝图 02：Action 系统与控制流结构化

本蓝图详细描述了 Rudra 在优化规则引擎（Action/Rule）以及控制流结构化分析（Structuring）上的实现细节。

## 1. Action 引擎与固定点迭代 (Optimization Engine)

Ghidra 的反编译过程是一个不断应用规则直到图不再变化的固定点过程。

### 核心调度逻辑：
- **ActionGroup**: 包含多个子 Action，支持 `rule_repeatapply` 属性。
- **ActionPool**: 规则池，维护一个从 `OpCode` 到 `Rule` 列表的映射。
- **固定点算法 (Fixed-point)**：
  ```rust
  loop {
      let mut modified = false;
      for action in active_actions {
          if action.apply(funcdata) > 0 {
              modified = true;
          }
      }
      if !modified { break; }
  }
  ```

### Rule 实现模式：
在 Rust 中，每个 `Rule` 建议实现为一个 Trait：
```rust
pub trait Rule {
    fn name(&self) -> &str;
    fn get_opcode(&self) -> OpCode; // 关注的操作码
    fn check_match(&self, op: &PcodeOp, data: &Funcdata) -> bool;
    fn apply(&self, op: &mut PcodeOp, data: &mut Funcdata) -> i32;
}
```
**关键规则分类**：
1. **数据流简化**：`RulePropagateCopy` (常量传播), `RuleSubvarSel` (子变量选择)。
2. **算术折叠**：`RuleDoubleInvert` (双重取反消除), `RuleCommute` (交换律应用)。
3. **副作用清理**：`ActionDeadCode` (基于引用计数的死代码消除)。

## 2. 控制流结构化 (Structuring Algorithm)

将扁平的基本块图转变为嵌套的控制流树（如 `if-then-else`, `while`）。

### A. 循环识别 (Loop Discovery)
- 使用 **Tarjan 强连通分量 (SCC)** 算法寻找循环。
- 识别循环入口（Header）和回边（Back-edge）。
- **Ghidra 特化**：处理多入口循环及不可约图（Irreducible graphs）。

### B. 结构折叠 (CollapseStructure)
实现一个贪心匹配器，从最内层块开始尝试匹配以下模式：
1. **If-Then-Else**: 
   - 匹配条件跳转块 `B`。
   - 识别 `True` 分支和 `False` 分支。
   - 寻找汇合点 `M = IPdom(B)`。
2. **While-Do / Do-While**:
   - 识别 Header 指向 Exit 的边。
3. **Switch (JumpTable)**:
   - 匹配 `BRANCHIND` 操作。
   - 调用 `JumpTable::recover` 获取目标地址数组。
   - 将目标地址映射回 `BlockId`。

## 3. 跳转表恢复状态机 (JumpTable State Machine)

Ghidra 的 `JumpTable` 恢复通常分为三个尝试阶段：
1. **Easy Match**: 匹配典型的指令序列（如 `LEA`, `CMP`, `JMP`）。
2. **Symbolic Emulation**: 使用 `EmulateFunction` 模拟执行，追踪索引变量的边界。
3. **Range Analysis**: 分析索引变量的 `nzm` (Non-Zero Mask) 和取值范围。

## 4. 对齐校验点 (Sensor Alignment)

- **Action Trace**: 在 `ActionGroup::apply` 拦截。比对 Rudra 和 Ghidra 谁先应用了某个 Rule。
- **Block ID Sync**: 拦截 `Funcdata::structureReset`。确保基本块的索引和属性（如 `is_loop_header`）完全一致。
- **JumpTable Targets**: 拦截 `rugra_observe_jumptable`。校验恢复出的分支总数和具体偏移。

---
*注：控制流结构化的成功标志是最终生成的结构化树（BlockGraph）的层级关系与 Ghidra 的 XML 导出完全重合。*