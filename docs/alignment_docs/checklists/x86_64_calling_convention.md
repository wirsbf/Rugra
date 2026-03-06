# Ghidra 对齐说明：x86_64 调用约定 (Calling Convention)

**[状态]**: 🔴 TODO  
**[目标模块]**: x86_64 架构下系统及用户函数的参数传递规则还原  
**[关联 Ghidra 源码位置]**: `Ghidra/Processors/x86/data/languages/x86-64.cspec` 及对应分析层  
**[关联 Rugra 源码位置]**: 待新建或补充 `src/analysis/calls.rs` 等模块  

---

## 1. 目标描述 (Description)

在反编译推导阶段，不仅需要识别函数的位置，还需要正确找出被调用函数究竟**使用了哪些寄存器或栈偏移作为形式参数**，并遵循了何种清理栈的规范（`__stdcall`, `__cdecl`, `__fastcall` 等）。
目前尚未建立与 Ghidra 的 `cspec` （Compiler Specification）驱动等价的传参规约动态推算系统，这导致所有通过栈传递的参数或者隐藏参数 (Hidden Return Pointer) 无法被正确识别和类型挂接。

## 2. Ghidra 的实现逻辑 (Ghidra Implementation)

- **数据结构**: 
  - 通过加载 `<compiler_spec>` 相关的 XML 定义树。
  - `ProtoModel` 类对 `__cdecl`, `__stdcall` 等概念进行分离开箱。
- **核心算法**:
  1. 通过支配与活跃度分析，收集入参点寄存器 (`RCX`, `RDX`, `R8`, `R9` 等) 或者出参寄存器 (`RAX`) 是否在其定义前被该函数块消费者所读取 (`Varnode::is_input() == true`)。
  2. 匹配 `cspec` 中的顺序模板分配规则，按字长给他们贴上实参编号。

## 3. Rugra 的对齐方案 (Rugra Approach)

待实现。

- [ ] **TODO: 步骤 1**: 在 Rust 端建立轻量的静态调用规约序列表（硬编码 Windows x64 与 System V AMD64 ABI）。
- [ ] **TODO: 步骤 2**: 改造数据流分析器，提取未定义但被读取的 `Varnode`，利用此序列与存活集求交配对。
- [ ] **TODO: 测试验证**: 编译各种带有混合传参的 C 代码片段进行 FFI 对拍还原断言测试。
