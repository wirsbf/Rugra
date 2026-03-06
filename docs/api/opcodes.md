# `opcodes.rs` API Reference (系统操作词汇大典)

**源代码路径**: `src/opcodes.rs`

## 模块说明 (Module Doc)

汇集了全量支持的 P-code 中间指令动作语表集合。
本模块内的所有枚举成员通过 `CPUI_` 的前缀严格致敬并对齐 Ghidra 内部的 `opcodes.hh` 枚举字典表。这些操作码构成了整个反编译架构“汇编泛化提纯”与“高级语言折叠”过程中的**原子词汇**。

该语料库不涉及高级控制结构语法树 (AST)，而全完是平面 SSA 层级的细粒计算操作。

---

## 导出的公共 API (Public API)

### `pub enum OpCode` (全量动作枚举字库)

表示 P-code IR 中唯一动作分类。由于设计用于表达泛型计算机行为，它们大多包含特定于有/无符号或者特种浮点运算的分裂表达（例如 `INT_DIV` 对应无符号，`INT_SDIV` 对应有符号，均由转译器自动判定装载）。

分类如下：

#### **1. 数据移动 (Data Movement)**
*   `CPUI_COPY`: 源变元值的跨节点直接平面拷贝分发。
*   `CPUI_LOAD` / `CPUI_STORE`: 横跨不同 Address Space 进行的内存指针存取取指。要求特定的地址计算先决推导完成。

#### **2. 算术运算 (Arithmetic Operations)**
*   `CPUI_INT_ADD` / `CPUI_INT_SUB` / `CPUI_INT_MULT`: 基本无符号/有符号等效加减乘三元操作。
*   `CPUI_INT_DIV` / `CPUI_INT_SDIV` / `CPUI_INT_REM` / `CPUI_INT_SREM`: 必须区分有无符号的整型计算（符号位敏感）。
*   `CPUI_INT_NEG` / `CPUI_INT_CARRY` / `CPUI_INT_SCARRY` / `CPUI_INT_SBORROW`: 对于一元求负及寄存器/标志位级进位/借位状态检测。

#### **3. 位域修剪运算 (Bitwise & Extension)**
*   `CPUI_INT_AND` / `CPUI_INT_OR` / `CPUI_INT_XOR` / `CPUI_INT_NOT`: 基本长整逻辑按位截修计算。
*   `CPUI_INT_LEFT` / `CPUI_INT_RIGHT` / `CPUI_INT_SRIGHT`: **(右移操作极为敏感！)** `RIGHT` 表示高位安全补零，而 `SRIGHT` (Arithmetic) 必须跟随原高位符号填充。
*   `CPUI_INT_ZEXT` (Zero Extension) / `CPUI_INT_SEXT` (Sign Extension) / `CPUI_TRUNC`: 长度与宽度的跨级变换，在不同的存储颗粒和推导期间（比如 AL -> EAX）是极其常出现的。

#### **4. 判定比对 (Comparison)**
此类操作码的强规约：**恒指输出位必须且仅能是一个长度为 1-byte, 值为 0 或 1 的布尔态 Varnode**。
*   `CPUI_INT_EQUAL` / `CPUI_INT_NOTEQUAL`
*   `CPUI_INT_LESS` / `CPUI_INT_LESSEQUAL` (针对无符号数值的纯数学高低排序比较)
*   `CPUI_INT_SLESS` / `CPUI_INT_SLESSEQUAL` (针对有符号体系的数值跨带高低比较)

#### **5. 浮点集 (Floating Point)**
略。前缀统一替换为 `CPUI_FLOAT_`（实现了所有对应整型的基础库、比对库及专有的类型/修剪截断 `CPUI_FLOAT_INT2FLOAT`, `CPUI_FLOAT_ROUND` 等）。

#### **6. 控制流越迁与黑洞调用 (Control Flow & Call)**
这些行为在基本阶段会导致当前 Basic Block 终止并撕裂。
*   `CPUI_BRANCH`: 函数域内的无条件跨控制块的地址飞越。
*   `CPUI_CBRANCH`: （唯一有判定条件的跳转！）必然且只受控联接于前面布尔判定的挂载口输出进行分支抉择。
*   `CPUI_CALL` / `CPUI_RETURN`: 标准的已知边界进入与离开破坏/退出副作用。
*   `CPUI_BRANCHIND` / `CPUI_CALLIND`: *(重灾区)* 在初期不确定落点的寄存器寻址或函数指针越阶行为，会导致大规模断流并亟需特异启发式推算辅助连回。
*   `CPUI_CALLOTHER`: 系统无法理解或者不在意实现的黑盒系统交互子（如 CPU 协处理器中断触发、特权陷阱、未知环境微指令）。

#### **7. 特殊拼接与聚合集 (Special Operations)**
*   `CPUI_PIECE` / `CPUI_SUBPIECE`: 把一对被物理寄存器拆分的 32 位值揉接为一个完整的 64 位值；反之从一串结构切分特异提取。
*   `CPUI_MULTIEQUAL`: **（SSA的灵魂结晶）** 即经典的 `Phi` 合并指令，存在于控制流的汇合点用以将多线汇集态在同一定义点闭环！
*   `CPUI_INDIRECT` / `CPUI_CPOOLREF` / `CPUI_NEW`: 专攻带混淆解算、全局静态大常量池抓取、以及高层级语言面向对象特征构造。
*   `CPUI_SEGMENTOP` / `CPUI_PTRADD`: x86 独有的老式段基址加偏移映射以及结构/多维数组内存漫游地址强加计算子。

#### 提供的方法
*   `pub fn name(&self) -> &'static str`: 获取这个操作动作短促响亮的精干名词（比如打印/导出为 `INT_SREM` 字符串字面量）。此宏命令也是 `fmt::Display` 的兜底挂载，用于日志打印排期或在前端进行 Graph/Tree UI 可视化呈现的标记位。
