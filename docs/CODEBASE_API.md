# 全局接口参考与核心代码白皮书 (API & Codebase Reference)

此文档展示了整个 `Rugra` 核心库内部所有的架构分层、文件划分职责、以及暴露的关键 API 抽象。它旨在帮助开发人员快速定位修改点与代码脉络。

---

## 核心层级概览 (Architecture Layers)

我们可将 `src/` 下分散的诸多文件和子系统按功能域划入如下五大逻辑层：
1. **基础寻址与存储层 (Memory & Addressing)**
2. **中间表示 (IR) 基础结构层**
3. **系统工作与转化流水线 (Subsystems)**
4. **反编译高级行为驱动 (Action System)**
5. **基础设施与跨层支持 (Infrastructure)**

---

## 1. 基础寻址与存储层 (Memory & Addressing)
处理底层内存模型与物理指针的表示形态，是所有模块与指令引用的最底层支撑：

*   **`src/address.rs`**: 包含了反编译器中最基础的 `Address` 结构体概念。封装了无符号长整型，能够应对基于任何物理地址乃至寄存器的唯一空间寻址抽象。
*   **`src/space.rs`**: 定义了 `AddrSpace` 和 `AddrSpaceManager`。管理所有隔离的虚拟存储区域（比如 `ram`, `register`, `const`, `unique`）。确保跨空间的加减计算被隔绝，提供基于前缀树或哈希映射的管理手段。
*   **`src/cover.rs`**: 提供针对某个特定的 Basic Block 或指令区域的代码覆盖范围表达，主要用于描述变量的生效区间 (Live Range/Scope)。

## 2. P-code IR 基础结构层 (IR Foundations)
这是从 Ghidra 迁移并复刻过来的静态单赋值 (SSA) 及数据流元操作层：

*   **`src/opcodes.rs`**: 全局唯一的 `OpCode` 巨型枚举，包罗了所有 P-code 虚拟机原生支持的微操作指令集 (如 `INT_ADD`, `CBRANCH`, `STORE` 等)。
*   **`src/pcoderaw.rs` / `src/op.rs`**: P-code 核心业务的骨架表达。内涵了类似 `PcodeOp` 或 `PcodeOpRaw` 等数据结构，它拥有自己的执行时序标号 (`SeqNum`) 以及前级输入指向/后级输出流出。
*   **`src/varnode.rs` / `src/variable.rs`**: 承载参数流转的结点。`Varnode` 定义了某个地址空间中的具象变元节点（附带生命期概念）。
*   **`src/block.rs`**: 定义基础块 `FlowBlock` / `BasicBlock`，以及基于树和有向图结构的图元控制流算法基底对象。

## 3. 主要工作流与转化子系统 (Subsystems)
真正完成干活的主干流程引擎目录（每一个目录下均有对应的更深的独立说明在 `src_ref/` 内）：

*   **`src/binary/`**: 挂接 `goblin` 解码宿主程序的重定位表、调试符号和装载分段。
*   **`src/disasm/`**: 将裸机字节流切片映射为 `iced-x86` 下的汇编助记符对象。
*   **`src/translator/`**: 利用 x86 特征匹配或模式规则产生原始的未净化版 P-code (Raw Pcode)。
*   **`src/analysis/`**: 整个应用的大脑。承载诸如**类型推论、数据流扩散、到达控制、和常量消除**等。
*   **`src/codegen/`**: 将提纯后的 `Pcode` 根据支配树关系重新折叠拼合，最后释放 C 代码。
*   **`src/pcode/`** (`program.rs` 等): `PcodeOperation` 流的管理者。
*   **`src/type_system/`**: 关于原始基本类型 (`INT`, `FLOAT`, `VOID`) 以及自定义的 `STRUCT` 等统一维护总线。

## 4. 高级行为驱动层 (Action System)
模拟了 Ghidra 的微命令（Action）与反应器（Rule）系统，基于访问者或钩子模式：

*   **`src/action.rs`**: 全局 `Action` Trait，所有代码块变换或者分析流程均可以被封装进一个 `Action` 中挂载执行。
*   **`src/coreaction.rs`**: 基于 `Action` 定义的内核级基本行为（如启动一次特定的死代码擦除扫荡）。
*   **`src/ruleaction.rs`**: 基于规则的优化转化表 (`Rule`)，例如特定的 `Add(x, 0) -> x` 等树上局部规则引擎匹配逻辑。
*   **`src/blockaction.rs`**: 专门基于控制图节点调度的特供 `Action` 结构。

## 5. 基础设施层 (Infrastructure & CLI)
串联这些复杂组件的大动脉与包装：

*   **`src/heritage.rs`**: 从 Ghidra 搬运的核心 "Heritage" (继承) 系统体系：负责执行把普通的非 SSA 全局访问节点（如操作某个固定的物理栈寄存器）转化为带版本号记录、具有多向关联的 `Varnode` 图层（SSA 化）的桥接管理器。
*   **`src/types.rs`**: 辅助数据结构支持。
*   **`src/typeop.rs`**: 指定基于各个不同类型及 Pcode OpCode 相遇时的类型变异计算法则（如“整型遇见指针将衍生出什么新类型”的运算法）。
*   **`src/ffi.rs`**: 提供和 C++ (Ghidra原生类环境) 对拍连接通信用的包装接口。
*   **`src/utils.rs`**: 供全局调用的静态辅助算法。
*   **`src/lib.rs` / `src/bin/`**: Rust 工程的通用导出挂载点及最终生成二进制命令程序的人机接口控制中心。
*   **`src/error.rs`**: 构建统一透明的内部异常逃逸分发路径。

---

如果需要深度阅读某个特有转换引擎的精确流程（例如具体分析树怎么长的），请移步 `docs/src_ref/` 下的相关模块手册！
