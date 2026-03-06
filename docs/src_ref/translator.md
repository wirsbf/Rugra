# 转译模块技术参考 (Translator Module)

本文档提供了 `src/translator` 模块（特指 x86-64 架构翻译后端）的核心实现逻辑的技术规范参考。

---

## 1. 主转译入口 (`x86_64.rs`)

### `X86_64Translator::translate`

**签名**:
```rust
fn translate(&self, instruction: &Instruction) -> Result<Vec<PcodeOperation>>
```

**输入**: 从二进制引擎(`iced-x86`)返回的一条机器指令。
**输出**: 等价于该汇编语义的 `PcodeOperation` 操作序组。

**核心逻辑**:
依据 `instruction.mnemonic` (助记符) 进行分发调度（如：`translate_mov`、`translate_add`等），交由专门的翻译逻辑通过 `PcodeBuilder` 汇编出对应的微指令集。

---

## 2. 数据与指令移动 (Data Movement)

### `translate_mov`
解析操作数，通过调用底层的 `store_operand(dest, source)` 逻辑写入值。注意：对于 32 位寄存器的写入，`store_operand` 会自动产生一条 `INT_ZEXT` 将其零扩展至对应的 64 位寄存器（例如写入 `EAX` 会零扩展至 `RAX`）。

### `translate_lea` (Load Effective Address)
目标是计算出地址数字，而不是地址解引用的值。
源码实现较为简化：通过生成一个 `Unique` 临时变量存放临时魔法值 `0xdeadbeef`（作为地址桩），然后直接发出 `COPY` 将该魔法桩塞进目的寄存器。**注意：当前版本中并未实现完整的 `[Base + Index*Scale + Disp]` 加法基址推演 P-code 生成。**

### `translate_push` 与 `translate_pop`
1. 先计算栈顶新偏移指令 (`RSP ± 8`) 
2. 随后触发内存 `STORE(space=ram, ptr=RSP, value=src)` 或 `LOAD(space=ram, ptr=RSP)`。

---

## 3. 控制流转译

### `translate_call` (函数调用)
若是目标直接明确（Direct Call），使用 `CALL(const_target)`。
若目标是寄存器引用或寻址计算结果（Indirect Call），使用 `CALLIND(target_var)` 取代。
注：真实的形参传递（入参注入）将放在 `src/analysis/calls.rs` 中二次推断，提升器阶段不做强行假定。

### `translate_jmp` 
判断若是硬编码直接跳转则释放 `BRANCH(target)`，如果是动态计算（间接）的话释放 `BRANCHIND`。
此处的明确分类是为了在生成控制流图(`CFG`) 时，能将难以预测的间接跳（如：跳转表、PLT Stubs等）单独标识，阻断错误的假定坠入执行。

### `translate_ret` (返回)
发射 `RETURN(inputs...)` 且需要强行在输入参数里绑死 `RAX/EAX/XMM0`等常见存根对象。
此举非常关键：这确保了数据流后置分析或者 “死代码消除”(DCE) Pass 不会因误判返回值没有使用者而在前向将核心逻辑删掉。