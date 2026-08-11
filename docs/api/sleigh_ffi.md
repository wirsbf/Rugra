# sleigh_ffi.rs

SLEIGH p-code 引擎的进程内 FFI 边界。`build.rs` 从锁定的 Ghidra
12.0.4 Decompiler C++ 源码编译 CORE + SLEIGH 运行时和
`rugra_sleigh.cpp`。Rust 通过版本化 C ABI 创建 `Sleigh`、安装 owned
内存映像，并把一次 `Sleigh::oneInstruction` 的完整观察结果深拷贝为
Rust DTO。

## SLEIGH-0002B 动态结果协议

`SleighCtx::one_instruction` 是本层的严格入口：

- 单次 C++ 调用同时返回真实 `step` 与全部 p-code，避免第二次解析改变
  context/缓存状态；
- op 按 `PcodeCacher::issued` 顺序、input 按 slot 顺序返回，无 64-op 或
  16-input 固定上限；
- `OK + step > 0 + ops.is_empty()` 保留合法 zero-op 指令，不能与异常混淆；
- output 可空；公开 DTO 用 `has_output==0` 表示空，此时 `output` 只是必须
  完全忽略的 default sentinel（其 identity 可与真实 ID 重合）。每个
  `VarnodeData*` 在一次指令内按“逐 op，先 output、再
  inputs”首次出现顺序获得 identity，保留跨 op 别名关系但不泄漏进程指针；
- LOAD/STORE 的 space-id input 将内部 `AddrSpace*` 规范化为 address-space
  index；候选值必须先命中 translator 注册空间的 pointer whitelist，未知值
  返回 typed error，绝不解引用任意整数。普通 constant（包括相对 p-code
  branch）不改写；
- `UnimplError`、`BadDataError`、`DataUnavailError`、`SleighError`、
  `LowlevelError`、`DecoderError`、标准与未知异常保持分型。message 先按原始
  bytes 保存，只有展示时才做 lossy UTF-8；只有 `UnimplError` 携带
  `instruction_length`，数值 0 仍表示字段存在。

C++ opaque result 始终由 `rugra_sleigh_result_destroy` 使用同一 allocator
释放。Rust 的 RAII guard 先验证 ABI version，再逐项拷贝固定宽度 wire
record；不会用 `Vec::set_len` 制造未初始化值，也不会用
`Vec::from_raw_parts` 接管 C++ 容器。

`RugraLoadImage` 在 `try_set_image` 返回前完整复制调用方 bytes。相对偏移按
锁定 `RawLoadImage::loadFill` 的无符号 `start - vma` 做 64 位模减；模减结果
不在 image 时抛 `DataUnavailError`，在 image 内但固定 16-byte fetch 跨过尾部
时复制有效前缀并补零。fixture 同时覆盖普通越界与 `UINT64_MAX → 0` 回绕。
为防止 `DisassemblyCache` 按旧地址命中解析树，当前 ABI 在首次 decode 或
`instruction_length` 后保守冻结 image/context，后续替换返回
`InvalidState`。这是 `RUGRA-GLUE` 生命周期策略，不是 Ghidra 行为等价结论。
包括首次失败后替换 image 再重试在内的精确 mutable-loader/cache 语义归
`SLEIGH-0002D`，必须以锁定 `Sleigh::reset` / `Sleigh::oneInstruction`
fixture 判定，不能预设需要重建 translator 或重放 spec。

`decode() -> Vec<PcodeOpC>`、`set_image()` 与 `set_context()` 仅是旧 lifter
的兼容桥：它们仍会折叠严格错误，不能用于 oracle 证据。生产调用链改用
严格结果、移除 lifter 内二次 input cap，并采用 SLEIGH step，分别属于
`SLEIGH-0002D` 与 `SLEIGH-FLOW-0001`。

## 尚未闭合的边界

- `load_pspec` / `simple_xml_find` / `get_attr` 是
  `SLEIGH-0002C/MISMATCH` 临时兼容层。它只扫 raw `<set>` tag，丢失
  `ContextInternal::decodeFromSpec` 的地址范围、explicit mask、tracked
  register 与子节点顺序，绝不构成行为等价证明。
- `new() -> Option`、legacy `instruction_length() -> Option` 以及固定 64-byte
  space/register name catalog 仍会压缩部分创建/metadata错误，未纳入本批次
  MATCH 范围。
- 锁定 x86-64 SLA 的 alignment 为 1 且没有 null-template constructor，无法
  自然触发 `UnimplError`；该分支实现了 typed transport，但保持 `UNTESTED`。
- 单 op 超过 16 个 input、delay-slot `step`、STORE space-id、OOM/标准/未知异常、
  `InvalidState` 与析构 fault injection 分支仍为 `UNTESTED`；动态协议已移除
  旧容量上限，但这些分支不能据实现形状升级 MATCH。
- 首次 decode（包括失败）后替换 image/context 会保守返回 `InvalidState`；
  真实 Ghidra mutable loader 的 error→replace→retry 生命周期留给
  `SLEIGH-0002D`，不属于本批 MATCH。
- 完整 pspec/cspec、长生命周期 parser cache、Flow 异常策略、space/opcode
  映射与最终反编译输出均不属于本层的窄域 raw ABI 结论。

## 锁定 oracle 验证

```bash
tools/run_sleigh_decode_oracle.sh
cargo test --offline --lib sleigh_ffi::tests -- --nocapture
cargo run --offline --example sleigh_test
```

oracle runner 使用锁定 commit
`e40ed13014025f82488b1f8f7bca566894ac376b` 的真实 CORE + SLEIGH 源码，
与 Rust FFI 对同一 SLA、显式 context、image/base/offset 运行同 schema
stdout direct diff。12 个 manifest case 覆盖 CPUID 78 ops/134 inputs、三种
zero-op NOP（含单字节尾部补零与 `UINT64_MAX -> 0` 模减回绕）、动态内存
MOV 的跨 op pointer alias、BadData、三种 DataUnavail、owned source mutation
以及成功后错误不泄漏；额外 reachability record 证明锁定 x86-64 无法触发
`UnimplError`。fixture metadata 记录 architecture、compiler spec、options、
输入指纹与全部 comparand hash。runner 对 12 个已覆盖 case 为 `MATCH`；因
`Unimpl` 及上列剩余分支仍为 `UNTESTED`，fixture overall status 是
`PARTIAL_MATCH`，模块继续保持 L2。
