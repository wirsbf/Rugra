# 全库 API 详细映射与参考手册 (API Reference)

该文档夹下的所有分类树与 Rust 代码库 (`src/`) 保持 **1:1 的绝对解构与目录映射**。

对于每一个 `src/**/*.rs` 文件，均在此有着同名对应的 `.md` 定义文档。它非常细致详尽地提取了文件中每一个向外暴漏 (`pub`) 的：
- 核心结构体 (`pub struct`)
- 宏命令、常量与枚举 (`pub enum` / `pub const`)
- 公共接口方法 (`pub fn`)
并绑定了对应的开发者注释 (`///`)！

**请按需进入对应的分层了解接口细节：**
- `address.md`, `space.md`, `cover.md` (基础寻址层)
- `varnode.md`, `variable.md`, `op.md`, `opcodes.md`, `pcoderaw.md`, `block.md` (指令与图元 IR 底层)
- `action.md`, `coreaction.md`, `ruleaction.md` (转换钩子层)
- `analysis/` (数据流/控制流算法群)
- `codegen/` (AST 恢复及 C 转译流)
- `translator/` (指令转译后端)

*(注：此目录的内容基架可以通过根目录的 `tools/generate_api_docs.py` 一键全量同步抽取！每次大版本发版需执行一次对齐)*
