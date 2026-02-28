# Rugra 文件结构重组计划

## 目标

将 Rugra 的代码结构调整为与 Ghidra C++ 反编译器一致，以便：
1. 更容易对照 Ghidra 源码实现
2. 保持 1:1 的文件映射关系
3. 便于后续的对拍验证

## Ghidra → Rugra 文件映射

### 核心基础设施 (Core Infrastructure)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `address.hh` | `src/address.rs` | `src/types.rs` (部分) | ⬜ 需移动 | P0 |
| `space.hh` | `src/space.rs` | `src/pcode/mod.rs` (AddressSpace) | ⬜ 需移动 | P0 |
| `pcoderaw.hh` | `src/pcoderaw.rs` | ❌ 不存在 | ⬜ 需创建 | P1 |
| `sleigh.hh` | `src/sleigh.rs` | `src/translator/` (部分) | ⬜ 需重组 | P1 |
| `sleighbase.hh` | `src/sleighbase.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |

### P-code 和 Varnode (Syntax Tree)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `varnode.hh` | `src/varnode.rs` | `src/pcode/varnode.rs` | ⬜ 需移动 | P0 |
| `op.hh` | `src/op.rs` | `src/pcode/ops.rs` + `program.rs` | ⬜ 需移动 | P0 |
| `opcodes.hh` | `src/opcodes.rs` | `src/pcode/ops.rs` (部分) | ⬜ 需拆分 | P0 |
| `opbehavior.hh` | `src/opbehavior.rs` | `src/analysis/rules/constants.rs` | ⬜ 需移动 | P1 |
| `typeop.hh` | `src/typeop.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |

### 函数和数据流 (Function Data)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `funcdata.hh` | `src/funcdata.rs` | `src/pcode/program.rs` (部分) | ⬜ 需重组 | P0 |
| `heritage.hh` | `src/heritage.rs` | `src/analysis/ssa.rs` | ⬜ 需移动 | P0 |
| `variable.hh` | `src/variable.rs` | `src/analysis/variables.rs` | ⬜ 需移动 | P1 |
| `high.hh` | `src/high.rs` | `src/analysis/high_variable.rs` | ⬜ 需移动 | P2 |

### 控制流 (Control Flow)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `block.hh` | `src/block.rs` | `src/analysis/mod.rs` (CFG 部分) | ⬜ 需提取 | P0 |
| `flow.hh` | `src/flow.rs` | `src/analysis/dataflow.rs` | ⬜ 需移动 | P1 |
| `graph.hh` | `src/graph.rs` | `src/analysis/mod.rs` (部分) | ⬜ 需提取 | P1 |
| `subflow.hh` | `src/subflow.rs` | ❌ 不存在 | ⬜ 需创建 | P3 |

### 优化和规则 (Actions & Rules)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `action.hh` | `src/action.rs` | `src/analysis/rules/mod.rs` | ⬜ 需移动 | P0 |
| `coreaction.hh` | `src/coreaction.rs` | ❌ 不存在 | ⬜ 需创建 | P1 |
| `ruleaction.hh` | `src/ruleaction.rs` | `src/analysis/rules/` | ⬜ 需重组 | P1 |
| `blockaction.hh` | `src/blockaction.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |

### 类型系统 (Type System)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `type.hh` | `src/type.rs` | `src/types.rs` | ⬜ 需重命名 | P0 |
| `cast.hh` | `src/cast.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |
| `cpool.hh` | `src/cpool.rs` | ❌ 不存在 | ⬜ 需创建 | P3 |

### 代码打印 (Code Printing)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `printlanguage.hh` | `src/printlanguage.rs` | `src/codegen/mod.rs` (部分) | ⬜ 需提取 | P1 |
| `printc.hh` | `src/printc.rs` | `src/codegen/mod.rs` | ⬜ 需移动 | P1 |
| `prettyprint.hh` | `src/prettyprint.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |

### 架构和二进制加载 (Architecture & Binary)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `architecture.hh` | `src/architecture.rs` | `src/types.rs` (Architecture) | ⬜ 需提取 | P1 |
| `loadimage.hh` | `src/loadimage.rs` | `src/binary/mod.rs` | ⬜ 需移动 | P2 |
| `database.hh` | `src/database.rs` | ❌ 不存在 | ⬜ 需创建 | P3 |

### 工具和实用 (Utilities)

| Ghidra C++ | Rugra Rust | 当前位置 | 状态 | 优先级 |
|-----------|-----------|---------|------|--------|
| `rangemap.hh` | `src/rangemap.rs` | `src/align/range.rs` | ⬜ 需移动 | P1 |
| `cover.hh` | `src/cover.rs` | ❌ 不存在 | ⬜ 需创建 | P2 |
| `emulate.hh` | `src/emulate.rs` | ❌ 不存在 | ⬜ 需创建 | P3 |

### Rugra 特有 (保留)

| 文件 | 用途 | 状态 |
|------|------|------|
| `src/align/` | 对齐验证（Rugra 特有） | ✅ 保留 |
| `src/ffi.rs` | FFI 接口（Rugra 特有） | ✅ 保留 |
| `src/error.rs` | 错误处理 | ✅ 保留 |
| `src/utils.rs` | 工具函数 | ✅ 保留 |

---

## 重组步骤

### 阶段 1: 核心基础 (P0 - 本周完成)

#### Step 1.1: 移动 Address 和 Space ✅

**状态**: 部分完成
- ✅ 创建 `src/address.rs` 
- ✅ 从 `src/types.rs` 提取 `Address` → `src/address.rs`
- ✅ 从 `src/pcode/mod.rs` 提取 `SeqNum` → `src/address.rs`
- ✅ 从 `src/align/range.rs` 移动 `Range`, `RangeList` → `src/address.rs`
- ✅ 更新 `src/lib.rs` 重新导出
- ✅ 更新所有引用，编译通过
- ⬜ 待完成：创建 `src/space.rs` (AddressSpace 仍在 pcode/mod.rs)

```bash
# 已完成：
# ✅ 1. 创建 src/address.rs
# ✅ 2. 移动 Address, SeqNum, Range, RangeList
# ✅ 3. 更新 src/lib.rs
# ✅ 4. 编译通过

# 待完成：
# - 创建 src/space.rs
# - 移动 AddressSpace 到 src/space.rs
```

**文件内容规划**:

`src/address.rs`:
```rust
//! Address representation (对应 Ghidra address.hh)
pub struct Address { ... }
pub struct Range { ... }
pub struct RangeList { ... }
```

`src/space.rs`:
```rust
//! Address spaces (对应 Ghidra space.hh)
pub enum AddressSpace { ... }
pub struct AddrSpace { ... }
pub struct ConstantSpace { ... }
pub struct UniqueSpace { ... }
```

#### Step 1.2: 创建 Space ✅

**状态**: 已完成
- ✅ 创建 `src/space.rs`
- ✅ 从 `src/pcode/mod.rs` 提取 `AddressSpace` → `src/space.rs`
- ✅ 创建 `ConstantSpace`, `UniqueSpace`, `OtherSpace`, `JoinSpace`, `OverlaySpace`
- ✅ 添加新的 space 变体：`Join`, `Overlay`
- ✅ 更新 `src/lib.rs` 重新导出
- ✅ 更新所有引用（包括 `src/pcode/varnode.rs` 的模式匹配）
- ✅ 编译通过

```bash
# 已完成：
# ✅ 1. 创建 src/space.rs
# ✅ 2. 移动 AddressSpace 枚举
# ✅ 3. 创建各种 Space 类型
# ✅ 4. 更新 src/lib.rs
# ✅ 5. 编译通过
```

#### Step 1.3: 移动 Varnode 和 Op

```bash
# 1. 移动文件
mv src/pcode/varnode.rs src/varnode.rs
mv src/pcode/ops.rs src/op.rs

# 2. 创建 opcodes.rs
touch src/opcodes.rs

# 3. 从 src/op.rs 提取 PcodeOp 枚举
# 移动到 src/opcodes.rs
```

**文件内容规划**:

`src/varnode.rs`:
```rust
//! Varnode definitions (对应 Ghidra varnode.hh)
pub struct Varnode { ... }
pub struct VarnodeBank { ... }
```

`src/op.rs`:
```rust
//! P-code operations (对应 Ghidra op.hh)
pub struct PcodeOp { ... }
pub struct PcodeOpBank { ... }
```

`src/opcodes.rs`:
```rust
//! OpCode enumeration (对应 Ghidra opcodes.hh)
pub enum OpCode {
    CPUI_COPY = 1,
    CPUI_LOAD = 2,
    // ... 完整的 OpCode 列表
}
```

#### Step 1.3: 重组 Funcdata
```bash
# 1. 创建 funcdata.rs
touch src/funcdata.rs

# 2. 从 src/pcode/program.rs 提取相关内容
# 3. 合并到 funcdata.rs
```

**文件内容规划**:

`src/funcdata.rs`:
```rust
//! Function data and control (对应 Ghidra funcdata.hh)
pub struct Funcdata { ... }
pub fn follow_flow() { ... }
pub fn structure_reset() { ... }
```

#### Step 1.4: 移动 Heritage (SSA)
```bash
mv src/analysis/ssa.rs src/heritage.rs
```

**文件内容规划**:

`src/heritage.rs`:
```rust
//! SSA construction (对应 Ghidra heritage.hh)
pub struct Heritage { ... }
pub fn heritage() { ... }
pub fn place_multiequals() { ... }
pub fn rename() { ... }
```

#### Step 1.5: 移动 Block 和 Flow
```bash
touch src/block.rs
touch src/flow.rs
touch src/graph.rs

# 从 src/analysis/mod.rs 提取 CFG
# 从 src/analysis/dataflow.rs 提取数据流
```

**文件内容规划**:

`src/block.rs`:
```rust
//! Basic blocks (对应 Ghidra block.hh)
pub struct BlockBasic { ... }
pub struct BlockGraph { ... }
pub fn calc_dominance() { ... }
```

#### Step 1.6: 移动 Action
```bash
mv src/analysis/rules/mod.rs src/action.rs
mkdir src/ruleaction/
mv src/analysis/rules/*.rs src/ruleaction/
```

---

### 阶段 2: 次要组件 (P1 - 下周完成)

- 移动 `opbehavior.rs`
- 创建 `printc.rs` 和 `printlanguage.rs`
- 移动 `variable.rs`
- 创建 `coreaction.rs`

---

### 阶段 3: 高级功能 (P2-P3 - 后续完成)

- 创建 `typeop.rs`
- 创建 `sleighbase.rs`
- 创建 `emulate.rs`
- 创建其他工具类

---

## 更新后的目录结构

```
src/
├── lib.rs                  # 主入口
├── error.rs               # 错误处理 (保留)
├── utils.rs               # 工具函数 (保留)
├── ffi.rs                 # FFI 接口 (保留)
│
├── address.rs             # ← address.hh
├── space.rs               # ← space.hh
├── varnode.rs             # ← varnode.hh
├── op.rs                  # ← op.hh
├── opcodes.rs             # ← opcodes.hh
├── opbehavior.rs          # ← opbehavior.hh
├── typeop.rs              # ← typeop.hh
│
├── funcdata.rs            # ← funcdata.hh
├── heritage.rs            # ← heritage.hh
├── variable.rs            # ← variable.hh
├── high.rs                # ← high.hh
│
├── block.rs               # ← block.hh
├── flow.rs                # ← flow.hh
├── graph.rs               # ← graph.hh
├── subflow.rs             # ← subflow.hh
│
├── action.rs              # ← action.hh
├── coreaction.rs          # ← coreaction.hh
├── blockaction.rs         # ← blockaction.hh
├── ruleaction/            # ← ruleaction.hh (拆分为多个文件)
│   ├── mod.rs
│   ├── algebra.rs
│   ├── constants.rs
│   └── dataflow.rs
│
├── type.rs                # ← type.hh (重命名自 types.rs)
├── cast.rs                # ← cast.hh
├── cpool.rs               # ← cpool.hh
│
├── sleigh.rs              # ← sleigh.hh
├── sleighbase.rs          # ← sleighbase.hh
├── pcoderaw.rs            # ← pcoderaw.hh
│
├── printlanguage.rs       # ← printlanguage.hh
├── printc.rs              # ← printc.hh
├── prettyprint.rs         # ← prettyprint.hh
│
├── architecture.rs        # ← architecture.hh
├── loadimage.rs           # ← loadimage.hh
├── database.rs            # ← database.hh
│
├── rangemap.rs            # ← rangemap.hh
├── cover.rs               # ← cover.hh
├── emulate.rs             # ← emulate.hh
│
├── align/                 # Rugra 特有：对齐验证
│   ├── mod.rs
│   ├── address.rs
│   ├── varnode.rs
│   ├── pcodeop.rs
│   ├── datatype.rs
│   ├── range.rs
│   └── runtime_verify.rs
│
└── bin/                   # 二进制程序
    └── rugra.rs
```

---

## 每个文件应该包含的内容

### `src/address.rs` (对应 address.hh)

```rust
//! Address representation and manipulation
//!
//! Corresponds to Ghidra's address.hh

/// Address in a specific address space
pub struct Address {
    space: SpaceId,
    offset: u64,
}

/// Sequence number (address + order)
pub struct SeqNum {
    addr: Address,
    order: u32,
}

/// Address range
pub struct Range {
    first: Address,
    last: Address,
}

/// List of address ranges
pub struct RangeList {
    ranges: Vec<Range>,
}

// 实现所有 Ghidra address.hh 中的方法
impl Address {
    pub fn new(offset: u64) -> Self { ... }
    pub fn is_null(&self) -> bool { ... }
    pub fn is_aligned(&self, alignment: u64) -> bool { ... }
}
```

### `src/varnode.rs` (对应 varnode.hh)

```rust
//! Varnode definitions
//!
//! Corresponds to Ghidra's varnode.hh

use crate::space::AddressSpace;
use crate::address::Address;

pub struct Varnode {
    space: AddressSpace,
    offset: u64,
    size: usize,
    flags: VarnodeFlags,
    def: Option<PcodeOpId>,
    uses: Vec<PcodeOpId>,
    // ... 其他字段
}

pub struct VarnodeBank {
    varnodes: Vec<Varnode>,
    // ... 管理 Varnode 的数据结构
}

// 实现所有 Ghidra varnode.hh 中的方法
```

### `src/op.rs` (对应 op.hh)

```rust
//! P-code operations
//!
//! Corresponds to Ghidra's op.hh

use crate::opcodes::OpCode;
use crate::varnode::Varnode;

pub struct PcodeOp {
    opcode: OpCode,
    output: Option<VarnodeId>,
    inputs: Vec<VarnodeId>,
    // ... 其他字段
}

pub struct PcodeOpBank {
    ops: Vec<PcodeOp>,
    // ... 管理 PcodeOp 的数据结构
}
```

---

## 实施检查清单

### 阶段 1 (本周)
- [x] 创建 `src/address.rs` ✅
- [x] 创建 `src/space.rs` ✅
- [ ] 移动 `src/varnode.rs`
- [ ] 移动 `src/op.rs`
- [ ] 创建 `src/opcodes.rs`
- [ ] 创建 `src/funcdata.rs`
- [ ] 移动 `src/heritage.rs`
- [ ] 创建 `src/block.rs`
- [ ] 创建 `src/flow.rs`
- [ ] 创建 `src/graph.rs`
- [ ] 移动 `src/action.rs`
- [x] 更新所有 `mod` 和 `use` 语句 ✅
- [x] 确保编译通过 ✅
- [ ] 运行所有测试

### 阶段 2 (下周)
- [ ] 创建 `src/opbehavior.rs`
- [ ] 创建 `src/printc.rs`
- [ ] 创建 `src/printlanguage.rs`
- [ ] 移动 `src/variable.rs`
- [ ] 创建 `src/coreaction.rs`
- [ ] 创建 `src/ruleaction/`
- [ ] 更新文档

### 阶段 3 (后续)
- [ ] 完成所有剩余文件
- [ ] 100% 对齐 Ghidra 结构

---

## 注意事项

1. **保持编译通过**: 每移动一个文件后都要确保 `cargo build` 通过
2. **更新测试**: 移动文件后更新相应的测试路径
3. **更新文档**: 同步更新 `ALIGNMENT_PROGRESS.md`
4. **Git 提交**: 每完成一个阶段提交一次，便于回滚
5. **逐个对照**: 每个文件都要对照 Ghidra 的 .hh 文件，确保包含所有关键方法

---

**开始时间**: 现在  
**预计完成**: 阶段 1 (本周), 阶段 2 (下周), 阶段 3 (后续)  
**责任人**: Rugra Team