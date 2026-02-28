# Rudra 实现蓝图 03：类型系统与变量推导

本蓝图详细描述了 Rudra 在高级语言类型恢复、类型格点传播以及逻辑变量（HighVariable）合并上的实现逻辑。

## 1. 类型系统数据结构 (Type System Data Layout)

Ghidra 的类型系统由 `TypeFactory` 管理，支持递归定义的结构体和指针。

### Rust 实现策略：
- **Interning / Memoization**: 使用 `Arc<Type>` 或 `StringInterner` 确保相同的类型描述符在内存中只有一份。
- **递归处理**：使用 `Indirection` 处理指针和链表结构，避免 Rust 结构体无限嵌套。
- **元类型 (Metatype)**：
    - `PTR`: 包含目标类型的 `Arc`。
    - `ARRAY`: 包含元素类型及数组长度。
    - `STRUCT`: 包含成员列表 `(offset, type, name)`。
    - `UNION`: 处理多路径解析。

## 2. 类型传播算法 (Type Propagation)

Rudra 必须复刻 Ghidra 的基于操作码的约束推导逻辑。

### A. 初始格点构建
- 常量 Varnode：根据数值大小推测最小类型（如 0x1 -> bool/char, 0x1234 -> int）。
- 寄存器/内存地址：根据 Sleigh 规范预定义的类型（如 RSP -> pointer）。

### B. 传播循环 (Fixed-point Lattice Propagation)
1. **收集所有 Varnode**：将其类型初始设为 `UNKNOWN`。
2. **应用 Op 约束**：
    - 例如 `INT_ADD v1, v2 -> v3`：约束 `type(v1) == type(v2) == type(v3)` 且必须是整数或指针。
    - 例如 `LOAD ptr_v -> data_v`：约束 `type(ptr_v)` 必须是 `PTR` 指向 `type(data_v)`。
3. **格点合并 (Lattice Join)**：
    - 当一个 Varnode 受到多个 Op 约束时，取其最大下界（GLB）。
    - 处理冲突：如果一个位置既被视为 `int` 又被视为 `float`，需要生成 `union` 或进行 `force cast`。

## 3. 逻辑变量合并 (Merging & HighVariable)

在 SSA 形式中，一个变量可能有几十个版本。Rudra 必须决定哪些版本在 C 语言中属于同一个变量。

### A. 生命周期冲突检测 (Cover Analysis)
- 实现 `Cover` 类：使用按地址排序的区间列表（Interval List）记录 Varnode 的定义点和使用点。
- **冲突判定**：如果两个 Varnode 的 `Cover` 在任何一个 P-code 点重叠，则它们不能合并（除非其中一个是副本）。

### B. 合并策略 (Merging Strategy)
1. **强制合并 (AddrTied)**：映射到相同物理内存或输入参数的 Varnode 强制合并。
2. **副本消除合并**：如果 `v2 = COPY v1` 且两者不冲突，则合并。
3. **类型一致性检查**：合并后的 `HighVariable` 必须拥有兼容的类型。

## 4. 函数原型解析 (Function Prototypes)

解析函数的“面相”，包括参数个数、位置和返回值。

### 关键步骤：
- **活跃分析 (Active Analysis)**：分析调用点（`CALL`）之后的寄存器使用情况，判断哪些寄存器是输入参数，哪些是返回值。
- **调用约定匹配**：对照 `ProtoModel` (从 `.cspec` 文件加载) 匹配参数压栈顺序和对齐。
- **清理垃圾参数**：识别并在 AST 中剔除那些被定义但从未使用的伪参数。

## 5. 对齐校验点 (Sensor Alignment)

- **Type Trace**: 拦截 `TypeOp::propagate()`。比对每一个 Varnode 被推导出的 `type_id`。
- **Merge Decision**: 拦截 `Merge::mergeTest()`。输出每一对 Varnode 及其合并失败的原因（Cover 冲突或类型冲突）。
- **Prototype Sync**: 拦截 `FuncProto::decode()`。校验解析出的参数列表和存储位置。

---
*注：类型系统的对齐直接决定了最终生成的 C 代码是否具有可读性（如 `*(int*)ptr` vs `array[i]`）。*