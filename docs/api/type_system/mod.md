# `type_system/` API Reference (Ghidra 对齐数据类型系统)

**源代码路径**: `src/type_system/`

## 模块说明 (Module Doc)

对应 Ghidra `type.hh` 及相关文件。本子目录实现了完整的数据类型管理体系——从基本标量类型到复合结构体/指针/数组/枚举，以及类型工厂（去重管理）和类型转换策略。

---

## 子文件导航

### `mod.rs` (入口与 Re-exports)

公开导出核心类型：`Datatype`, `TypeBase`, `TypeField`, `TypeMetatype`, `type_flags`, `TypeFactory`, `CastStrategy`, `CastStrategyC`。

---

### `datatype.rs` (数据类型定义层)

#### `pub enum TypeMetatype` (类型元分类)

`Unknown`, `Void`, `Bool`, `Int`, `Uint`, `Float`, `Pointer`, `Array`, `Struct`, `Union`, `Enum`, `Code`, `Spacebase` — 与 Ghidra `type_metatype` 完全对齐。

#### `pub mod type_flags` (类型属性标志)

`CORETYPE` (核心内建类型) / `CHARTYPE` (字符类型) / `ENUMTYPE` / `TYPEDEF` / `VARLENGTH` (可变长) / `UTF16` / `UTF32` / `OPAQUE_STRUCT` 等。

#### `pub struct TypeBase` (类型基类)

所有类型变体内嵌的公共字段：`name`, `size`, `metatype`, `id`, `flags`。

#### `pub enum Datatype` (类型和类型枚举)

*   `Void(TypeBase)` / `Base(TypeBase)`: 标量简单类型。
*   `Pointer(TypePointer)`: 含 `ptr_to: Arc<Datatype>` 和 `wordsize`。
*   `Array(TypeArray)`: 含 `array_of` 和 `num_elements`。
*   `Struct(TypeStruct)` / `Union(TypeUnion)`: 含 `fields: Vec<TypeField>`。
*   `Enum(TypeEnum)`: 含 `values: BTreeMap<u64, String>`。
*   `Code(TypeCode)`: 含可选的 `FuncProto`。
*   `Spacebase(TypeSpacebase)`: 栈帧/寄存器组的类型化抽象。

统一接口：`get_name()`, `get_size()`, `get_metatype()`, `get_id()`, `get_flags()`, `is_coretype()`, `is_variable_length()`。

---

### `typefactory.rs` (类型工厂与去重管理器)

#### `pub struct TypeFactory`

*   `pub fn new(ptr_size: usize) -> Self`: 创建并自动初始化核心类型（void/bool/int{1,2,4,8}/uint{1,2,4,8}/float/double）。
*   `pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>>`: 按名查找。
*   `pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype>`: 获取/创建指针类型（自动去重）。
*   `pub fn get_array(&mut self, ...) -> Arc<Datatype>`: 获取/创建数组类型。
*   `pub fn create_struct(...)` / `pub fn set_fields(...)`: 创建并设置结构体字段。
*   `pub fn clear_non_core(&mut self)`: 清除所有非核心类型，用于分析重置。

---

### `cast.rs` (类型转换策略)

#### `pub trait CastStrategy` (转换决策接口)

*   `is_cast_implied(out, in) -> bool`: 判断是否可以隐式转换。
*   `cast_standard(out, in) -> Option<Arc<Datatype>>`: 返回需要的显式转换类型。
*   `check_int_promotion_for_extension/compare(...)`: C 语言整数提升规则。

#### `pub struct CastStrategyC` (C 语言转换策略)

实现了标准 C 语言的隐式转换规则：
*   同元类型中，输出 ≥ 输入大小时隐式转换。
*   数组→指针隐式转换。
*   指针→布尔隐式转换。
*   小于 `promote_size` (通常为 4) 的整数/布尔/枚举在运算时自动提升。
