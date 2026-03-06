# `prettyprint.rs` API Reference (Token 发射与格式化框架)

**源代码路径**: `src/prettyprint.rs`

## 模块说明 (Module Doc)

对应 Ghidra `prettyprint.hh`。定义了反编译输出层的**通用 Token 发射接口**。无论最终输出是纯文本、带标记的 XML、还是 HTML 高亮视图，都必须通过实现 `Emit` Trait 来统一驱动。

---

## 导出的公共 API (Public API)

### `pub trait Emit` (Token 发射契约)

所有输出后端必须实现的接口：
*   **结构控制**: `begin_block()` / `end_block()` — 花括号域的打开/关闭；`open_paren()` / `close_paren()` — 圆括号；`begin_function()` / `end_function()` — 函数级边界。
*   **标记语义**: `tag_type(text, id)` / `tag_variable(text, id)` / `tag_op(text)` / `tag_field(text, id)` / `tag_func_name(text, id)` / `tag_comment(text)` / `tag_label(text)` — 为 IDE 级前端提供带语义分类的 Token 标注能力（点击变量名可跳转、类型名可高亮等）。
*   **原始输出**: `print(text)` — 无标记的裸文本发射。

---

### `pub struct EmitNoMarkup` (纯文本发射器)

最简朴的实现——将所有 Token 直接拼接为纯文本字符串，自动处理缩进。
*   `pub fn get_output(self) -> String`: 消耗自身并返回最终拼装好的文本结果。
