# Rugra 文件结构重组进度报告

## 📊 总体进度

**当前阶段**: 阶段 1 - 核心基础 (P0)  
**完成度**: 30% (3/10 步骤)  
**编译状态**: ✅ 通过  
**最后更新**: 2024

---

## ✅ 已完成步骤

### Step 1.1: 创建 `src/address.rs` ✅

**对应 Ghidra**: `address.hh`

**完成内容**:
- ✅ `Address` 结构体 - 内存地址表示
- ✅ `SeqNum` 结构体 - P-code 操作序列号
- ✅ `Range` 结构体 - 地址范围
- ✅ `RangeList` 结构体 - 地址范围列表
- ✅ 所有 Ghidra 方法的对应实现
- ✅ 完整的单元测试

**文件位置**: `src/address.rs` (465 行)

**重要变更**:
```rust
// 从 src/types.rs 移动
pub struct Address(u64);

// 从 src/pcode/mod.rs 移动
pub struct SeqNum { pub addr: Address, pub order: u32 }

// 从 src/align/range.rs 移动
pub struct Range { first: Address, last: Address }
pub struct RangeList { ranges: Vec<Range> }
```

---

### Step 1.2: 创建 `src/space.rs` ✅

**对应 Ghidra**: `space.hh`

**完成内容**:
- ✅ `AddressSpace` 枚举 - 地址空间类型
- ✅ `ConstantSpace` - 常量空间
- ✅ `UniqueSpace` - SSA 临时变量空间
- ✅ `JoinSpace` - 组合空间
- ✅ `OverlaySpace` - 覆盖空间
- ✅ `OtherSpace` - 自定义空间
- ✅ 完整的单元测试

**文件位置**: `src/space.rs` (431 行)

**重要变更**:
```rust
// 从 src/pcode/mod.rs 移动并扩展
pub enum AddressSpace {
    Ram,
    Register,
    Unique,
    Const,
    Stack,
    Join,      // 新增
    Overlay,   // 新增
    Other(SpaceId),
}

// 新增的 Space 类型
pub struct UniqueSpace { ... }  // SSA 临时变量分配器
pub struct JoinSpace { ... }    // 寄存器组合
pub struct OverlaySpace { ... } // 内存覆盖
```

---

### Step 1.3: 移动 `src/varnode.rs` 和 `src/op.rs` ✅

**对应 Ghidra**: `varnode.hh`, `op.hh`

**完成内容**:
- ✅ `src/pcode/varnode.rs` → `src/varnode.rs`
- ✅ `src/pcode/ops.rs` → `src/op.rs`
- ✅ 更新所有模块引用
- ✅ 更新导入路径
- ✅ 编译通过

**文件位置**:
- `src/varnode.rs` - Varnode 定义
- `src/op.rs` - P-code 操作定义

**重要变更**:
```rust
// src/varnode.rs
use crate::space::AddressSpace;  // 更新导入

// src/pcode/mod.rs
pub use crate::varnode::*;  // 从子模块改为顶层模块
pub use crate::op::*;
```

---

## 📁 当前文件结构

### 新的顶层模块（对齐 Ghidra）

```
src/
├── address.rs         ✅ ← address.hh
├── space.rs           ✅ ← space.hh
├── varnode.rs         ✅ ← varnode.hh
├── op.rs              ✅ ← op.hh
├── lib.rs
├── error.rs
├── ffi.rs
├── types.rs           (保留 Architecture 等)
│
├── pcode/             (简化为 Program 等)
│   ├── mod.rs
│   └── program.rs
│
├── analysis/
├── codegen/
├── binary/
├── disasm/
├── translator/
└── align/
```

### 对比：重组前 vs 重组后

| 模块 | 重组前 | 重组后 | 对应 Ghidra |
|------|--------|--------|-------------|
| Address | `src/types.rs` | `src/address.rs` | `address.hh` ✅ |
| SeqNum | `src/pcode/mod.rs` | `src/address.rs` | `address.hh` ✅ |
| Range | `src/align/range.rs` | `src/address.rs` | `address.hh` ✅ |
| AddressSpace | `src/pcode/mod.rs` | `src/space.rs` | `space.hh` ✅ |
| Varnode | `src/pcode/varnode.rs` | `src/varnode.rs` | `varnode.hh` ✅ |
| PcodeOp | `src/pcode/ops.rs` | `src/op.rs` | `op.hh` ✅ |

---

## 🚧 下一步计划

### Step 1.4: 创建 `src/opcodes.rs` (下一个)

**对应 Ghidra**: `opcodes.hh`

**任务**:
- [ ] 从 `src/op.rs` 提取 `PcodeOp` 枚举
- [ ] 创建完整的 OpCode 常量定义
- [ ] 添加 OpCode 名称映射
- [ ] 更新 `src/op.rs` 引用

**预期结构**:
```rust
// src/opcodes.rs
pub const CPUI_COPY: OpCode = 1;
pub const CPUI_LOAD: OpCode = 2;
// ... 75+ opcodes

pub enum PcodeOp { ... }
```

---

### Step 1.5: 创建 `src/funcdata.rs`

**对应 Ghidra**: `funcdata.hh`

**任务**:
- [ ] 从 `src/pcode/program.rs` 提取函数数据结构
- [ ] 创建 `Funcdata` 主结构
- [ ] 实现 `follow_flow()` 等核心方法

---

### Step 1.6: 移动 `src/heritage.rs` (SSA)

**对应 Ghidra**: `heritage.hh`

**任务**:
- [ ] `src/analysis/ssa.rs` → `src/heritage.rs`
- [ ] 实现 `heritage()`, `place_multiequals()`, `rename()`

---

### Step 1.7: 创建 `src/block.rs`

**对应 Ghidra**: `block.hh`

**任务**:
- [ ] 从 `src/analysis/mod.rs` 提取 CFG
- [ ] 创建 `BlockBasic`, `BlockGraph`
- [ ] 实现 `calc_dominance()`

---

### Step 1.8: 移动 `src/action.rs`

**对应 Ghidra**: `action.hh`

**任务**:
- [ ] `src/analysis/rules/mod.rs` → `src/action.rs`
- [ ] 创建 `src/ruleaction/` 目录

---

## 📊 对齐统计

| 分类 | Ghidra 文件 | Rugra 文件 | 状态 |
|------|-------------|-----------|------|
| 核心基础 | address.hh | src/address.rs | ✅ 完成 |
| 核心基础 | space.hh | src/space.rs | ✅ 完成 |
| P-code | varnode.hh | src/varnode.rs | ✅ 完成 |
| P-code | op.hh | src/op.rs | ✅ 完成 |
| P-code | opcodes.hh | src/opcodes.rs | ⬜ 计划中 |
| 函数数据 | funcdata.hh | src/funcdata.rs | ⬜ 计划中 |
| SSA | heritage.hh | src/heritage.rs | ⬜ 计划中 |
| 控制流 | block.hh | src/block.rs | ⬜ 计划中 |
| 优化 | action.hh | src/action.rs | ⬜ 计划中 |

**完成度**: 4/9 核心文件 (44%)

---

## ✅ 验证清单

- [x] `src/address.rs` 编译通过
- [x] `src/space.rs` 编译通过
- [x] `src/varnode.rs` 编译通过
- [x] `src/op.rs` 编译通过
- [x] 所有测试通过
- [x] 无编译警告（除预期的 unused）
- [x] 文档注释包含 Ghidra 对应信息
- [x] 模块正确重新导出

---

## 🎯 里程碑

### 阶段 1: 核心基础 (P0) - 本周
- [x] Step 1.1: address.rs ✅
- [x] Step 1.2: space.rs ✅
- [x] Step 1.3: varnode.rs + op.rs ✅
- [ ] Step 1.4: opcodes.rs
- [ ] Step 1.5: funcdata.rs
- [ ] Step 1.6: heritage.rs
- [ ] Step 1.7: block.rs
- [ ] Step 1.8: action.rs

**目标**: 完成所有 P0 文件的重组

### 阶段 2: 次要组件 (P1) - 下周
- [ ] opbehavior.rs
- [ ] printc.rs
- [ ] printlanguage.rs
- [ ] variable.rs
- [ ] coreaction.rs

### 阶段 3: 高级功能 (P2-P3) - 后续
- [ ] typeop.rs
- [ ] sleighbase.rs
- [ ] emulate.rs
- [ ] 其他工具类

---

## 📝 重要说明

1. **保持编译通过**: 每移动一个文件后都确保 `cargo build` 成功
2. **文档对齐**: 每个文件顶部都注释对应的 Ghidra 文件
3. **测试保留**: 所有原有测试保持可用
4. **向后兼容**: 通过 re-export 保持旧代码可用
5. **逐步推进**: 不要一次移动太多文件，确保稳定性

---

## 🔗 相关文档

- [完整重组计划](RESTRUCTURE_PLAN.md)
- [对齐进度](ALIGNMENT_PROGRESS.md)
- [验证指南](docs/VERIFICATION_GUIDE.md)

---

**下一步行动**: 执行 Step 1.4 - 创建 `src/opcodes.rs`
