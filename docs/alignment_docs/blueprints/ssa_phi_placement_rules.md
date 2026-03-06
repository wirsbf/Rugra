# Ghidra 对齐蓝图：SSA Phi 节点强置规则 (Phi Node Placement)

**[状态]**: 🔴 TODO  
**[目标模块]**: 结构化控制流下的数据并发交汇处理机制  
**[关联 Ghidra 源码位置]**: `Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc: Heritage::buildPhiNodes`  
**[关联 Rugra 源码位置]**: `src/heritage.rs`  

---

## 1. 目标描述 (Description)

在将非 SSA 形态（存在对同一个寄存器被多处指令赋值的覆盖情况）提纯转化为完全静态单赋值网络时，不仅需要利用支配边界 (Dominance Frontier) 建立 `MULTIEQUAL` (Phi) 节点，更要在一些诸如“永远死循环无法退出”、“虚假分支”的情况下规避无效 Phi 的构造。
Rugra 目前初版虽然搭起了支配树骨架（见 `src/block.rs`），但由于欠缺全量的 `heritage.cc` 内的启发式重排过滤法则，所生成的 `Phi` 函数远比 Ghidra 臃肿。这极度妨碍了后期代数坍缩。

## 2. Ghidra 的实现逻辑 (Ghidra Implementation)

- **核心算法**:
  - `Heritage` 管理类专门负责。该类内部拥有一套层级结构（`LocationMap`）：根据地址空间类型 (Registers / Stack 等) 决定分析阶段进行分步延缓（`delay`）。
  - 例如，对于别名严重受损情况下的栈区或者 `Unique` 变量，采取不同激进程度的值流聚合方法，而非无差别按图强插 Phi 节点。

## 3. Rugra 的对齐方案 (Rugra Approach)

待深入改造实现。

- [ ] **TODO: 步骤 1**: 扩充 `src/heritage.rs`，不仅执行标准支配算法，必须实现栈深度检测延迟 (`heritage_delay`) 变量恢复。
- [ ] **TODO: 步骤 2**: 研究并对拍死代码图 (`DEAD` flag block) 下对于 Phi 的激进斩杀策略。
