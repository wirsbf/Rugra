# 辅助脚本工具库 (Tools & Scripts)

此处归档所有用于项目测试辅助、Ghidra API 挂钩导出、一致性检测对拍的各种外部脚本（如 Python、Shell 脚本等）。不要将它们零散地扔在 Rust 项目根目录下。

目前主要脚本有：
- `ffi_test.py`: 涉及通过 C++ FFI 联调的一些绑定与驱动测试段。
- `ghidra_export.py`: 挂载在 Ghidra 原生环境中执行，用于将其内部的 P-code 数据导出为我们可以对比的形式。
- `pcode_compare_test.py`: 自动比较我们的 P-code 生成串与 Ghidra 原生串的微小差异脚本。
