# `printlanguage.rs` API Reference (打印语言抽象框架)

**源代码路径**: `src/printlanguage.rs`

## 模块说明 (Module Doc)

对应 Ghidra `printlanguage.hh`。定义了将反编译产物输出为**特定编程语言**的统一抽象接口。当前唯一的实现是 `PrintC`（C 语言），但该框架支持未来添加更多语言后端（如 Go、Rust 等）。

---

## 导出的公共 API (Public API)

### `pub trait PrintLanguage` (打印语言接口)

**本 Trait 是 `printc.rs` 等具体语言打印器的基类契约。** 它规定了将反编译 IR 转化为源代码所需的全部方法签名：

#### 发射器管理
*   `fn get_emit(&mut self) -> &mut dyn Emit`: 获取底层 Token 发射器。
*   `fn set_emit(&mut self, emit: Box<dyn Emit>)`: 替换底层发射器。

#### 文档级发射
*   `fn doc_function(&mut self, fd: &Funcdata)`: 发射完整的函数定义。
*   `fn doc_all_proto(&mut self, proto: &FuncProto)`: 发射函数原型签名。
*   `fn doc_variable_decl(&mut self, vn: &Varnode)`: 发射变量声明。
*   `fn doc_statement(&mut self, op: &PcodeOp)`: 发射单条语句。

#### 操作码级发射
*   `fn op_copy(...)` / `fn op_load(...)` / `fn op_store(...)`: 数据操作。
*   `fn op_binary(...)` / `fn op_unary(...)`: 算术/逻辑操作。
*   `fn op_multiequal(...)` / `fn op_indirect(...)`: SSA/副作用操作。
*   `fn op_call(...)` / `fn op_return(...)`: 控制流操作。

#### 类型与变量
*   `fn push_type(&mut self, dt: &Datatype)`: 发射类型标记。
*   `fn push_varnode(&mut self, vn: &Varnode, op: Option<&PcodeOp>)`: 发射变量名标记。

---

### `pub struct PrintLanguageCapability` (语言注册能力对象)

用于在全局注册表中声明"本系统支持打印 C 语言"的能力加载机制。
