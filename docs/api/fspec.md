# `fspec.rs` API Reference (函数原型与调用规约)

**源代码路径**: `src/fspec.rs`

## 模块说明 (Module Doc)

对应 Ghidra `fspec.hh`。管理函数签名原型 (Prototype) 和调用点规约 (Call Specification)。
在反编译中，正确识别函数的参数传递方式、返回值存储位置和栈清理责任方是高质量输出的命脉。

---

## 导出的公共 API (Public API)

### `pub mod protoparam_flags` (参数属性标志)

*   `HIDDEN_RETURN`: 此参数实际上是编译器为大型返回值插入的隐藏指针（如返回结构体时，第一个参数实为输出缓冲区地址）。
*   `THIS_POINTER`: C++ 方法的隐式 `this` 指针。
*   `TYPE_LOCKED` / `NAME_LOCKED`: 用户或分析已锁定此参数的类型/名称，后续推导不得覆盖。

### `pub struct ProtoParameter` (单个函数参数)

*   **`pub name: String`**: 参数名称（如 `argc`）。
*   **`pub data_type: Arc<Datatype>`**: 参数的推断类型。
*   **`pub address: Address`**: 存储位置（寄存器偏移或栈偏移）。
*   `pub fn is_this_pointer(&self) -> bool` / `pub fn is_type_locked(&self) -> bool`: 属性判断快捷方法。

---

### `pub struct FuncProto` (函数原型签名)

完整描述一个函数的调用接口：
*   **`pub return_type: Arc<Datatype>`**: 返回值类型。
*   **`pub parameters: Vec<ProtoParameter>`**: 形式参数列表。
*   **`pub calling_convention: String`**: 调用约定名（`__cdecl`, `__stdcall`, `__fastcall` 等）。
*   **`pub is_dotdotdot: bool`**: 是否为可变参数函数。
*   `pub fn add_parameter(...)` / `pub fn num_params()` / `pub fn get_param(...)`: 参数管理方法。

---

### `pub struct FuncCallSpecs` (调用点规约)

描述函数内部某个具体 `CALL` 指令的调用细节：
*   **`pub op_addr: Address`**: 调用指令自身的地址。
*   **`pub entry_addr: Option<Address>`**: 被调用目标的入口地址（间接调用时可能为 `None`）。
*   **`pub prototype: FuncProto`**: 此调用点使用的函数原型。
