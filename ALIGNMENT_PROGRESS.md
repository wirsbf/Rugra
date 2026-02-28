# Rugra-Ghidra Alignment Verification Progress

本文档追踪 Rugra 与 Ghidra 反编译器核心类的对齐验证进度。

> **⚠️ 重要声明**: 当前进度仅完成**静态类型对齐**，**不能保证**与 Ghidra 的运行时输出完全一致。详见 [验证指南](docs/VERIFICATION_GUIDE.md)。

## 总体进度

- **静态对齐完成**: 7/50+ 核心类 ✅
- **运行时验证**: 0% ❌（未实现）
- **当前阶段**: 01 Core Infrastructure（静态对齐）
- **关键缺失**: P-code 生成对拍、SSA 一致性验证、端到端测试
- **下一步**: 实现运行时验证框架（见 `src/align/runtime_verify.rs`）

---

## ⚠️ 验证层次说明

### ✅ Level 1: 静态类型对齐（已完成）
- 数据结构字段对齐（Address, Varnode, PcodeOp 等）
- 验证函数实现
- 单元测试覆盖
- **限制**: 仅验证数据结构，不验证算法行为

### ❌ Level 2: 运行时对拍（未实现）
- 常量求值结果比对
- P-code 生成序列比对
- SSA 版本号验证
- 控制流图结构验证
- **状态**: 框架已创建（`runtime_verify.rs`），但未集成 Ghidra FFI

### ❌ Level 3: 端到端验证（未实现）
- 完整反编译输出比对
- 真实二进制测试（curl 等）
- 语义等价性验证

---

## ✅ 已完成的静态对齐验证

### 01. Core Infrastructure (address.hh)

#### ✅ Address
- **文件**: `src/align/address.rs`
- **验证函数**: `verify_address()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - SpaceID ✅
  - Offset ✅

#### ✅ SeqNum
- **文件**: `src/align/address.rs`
- **验证函数**: `verify_seqnum()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - Address ✅
  - Order/Time ✅

### 02. Syntax Tree (varnode.hh, op.hh)

#### ✅ Varnode
- **文件**: `src/align/varnode.rs`
- **验证函数**: `verify_varnode()`, `verify_varnode_list()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - Space ✅
  - Offset ✅
  - Size ✅
  - Version (SSA) ✅

#### ✅ PcodeOp / PcodeOperation
- **文件**: `src/align/pcodeop.rs`
- **验证函数**: `verify_opcode()`, `verify_operation()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - Opcode (完整映射表) ✅
  - Input list ✅
  - Output ✅
  - SeqNum ✅

### 06. Type System (type.hh)

#### ✅ DataType
- **文件**: `src/align/datatype.rs`
- **验证函数**: `verify_datatype()`, `verify_struct_layout()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - Name ✅
  - Size ✅
  - Metatype (ptr, array, struct) ✅
  - Struct field layout ✅

#### ✅ Range
- **文件**: `src/align/range.rs`
- **验证函数**: `verify_range()`, `verify_contains()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - First/Last address ✅
  - contains() ✅
  - size() ✅
  - overlaps() ✅

#### ✅ RangeList
- **文件**: `src/align/range.rs`
- **验证函数**: `verify_range_list()`
- **测试**: ✅ 通过
- **关键属性对齐**:
  - insertRange() / removeRange() ✅
  - inRange() ✅
  - merge() ✅
  - numRanges() ✅

---

## 🚧 正在进行

### Runtime Verification Framework
- **文件**: `src/align/runtime_verify.rs`
- **状态**: 框架已创建，等待 Ghidra FFI 集成
- **功能**:
  - ✅ 验证统计收集
  - ✅ 差异记录系统
  - ✅ 报告生成
  - ❌ Ghidra FFI 调用（需要 `once_cell` 依赖和 FFI 库编译）
  - ❌ 实际运行时测试

---

## 📋 待完成清单

### 01. Core Infrastructure (pcoderaw.hh)

#### ⬜ PcodeOpRaw
- **需要验证**:
  - [ ] `addInput()` / `clearInputs()`
  - [ ] `decode()`
  - [ ] `setOutput()` / `setBehavior()`

### 01. Core Infrastructure (sleigh.hh)

#### ⬜ Sleigh
- **需要验证**:
  - [ ] `initialize()`
  - [ ] `printAssembly()`
  - [ ] `oneInstruction()`
  - [ ] `instructionLength()`

### 02. Syntax Tree (op.hh)

#### ⬜ PcodeOpBank
- **需要验证**:
  - [ ] `begin()` / `end()` iterators
  - [ ] `markAlive()` / `markDead()`
  - [ ] `changeOpcode()`
  - [ ] `destroy()` / `destroyDead()`

#### ⬜ VarnodeBank
- **需要验证**:
  - [ ] `beginDef()` / `endDef()`
  - [ ] `beginLoc()` / `endLoc()`
  - [ ] `makeFree()` / `replace()`
  - [ ] `hasInputIntersection()`

### 03. SSA and Heritage

#### ⬜ Heritage
- **预期文件**: `src/align/heritage.rs`
- **需要验证**:
  - [ ] `heritage()` (主入口)
  - [ ] `placeMultiequals()` (Phi 节点插入)
  - [ ] `rename()` (SSA 重命名)

### 04. Control Flow

#### ⬜ BlockGraph
- **预期文件**: `src/align/block.rs`
- **需要验证**:
  - [ ] `calcDominance()`
  - [ ] `buildLoop()`
  - [ ] Basic block 结构对齐

### 05. Actions and Rules

#### ⬜ ActionGroup / Action
- **预期文件**: `src/align/action.rs`
- **需要验证**:
  - [ ] `apply()` (规则应用)
  - [ ] `ActionDeadCode`
  - [ ] `ActionNameVars`

---

## 📊 对齐验证统计

### 静态对齐进度
| 类别 | 已完成 | 总数 | 进度 |
|------|--------|------|------|
| Core Infrastructure | 4 | 10+ | 40% ✅ |
| Syntax Tree | 2 | 8+ | 25% ✅ |
| Type System | 1 | 5+ | 20% ✅ |
| SSA/Heritage | 0 | 5+ | 0% ⬜ |
| Control Flow | 0 | 5+ | 0% ⬜ |
| Actions | 0 | 10+ | 0% ⬜ |

### 运行时验证进度
| 验证类型 | 状态 | 说明 |
|---------|------|------|
| 常量求值对拍 | ❌ | FFI 未集成 |
| P-code 生成对拍 | ❌ | 未实现 |
| SSA 版本号验证 | ❌ | 未实现（关键！） |
| CFG 结构验证 | ❌ | 未实现 |
| 端到端输出比对 | ❌ | 未实现 |

**整体一致性保证**: ❌ **无法保证**

---

## 🔧 运行验证测试

### 静态对齐测试（可运行 ✅）
```bash
# 运行所有静态对齐测试
cargo test --lib align::

# 运行特定模块测试
cargo test --lib align::address::tests
cargo test --lib align::varnode::tests
cargo test --lib align::pcodeop::tests
cargo test --lib align::datatype::tests
cargo test --lib align::range::tests
```

### 运行时验证测试（需要环境配置 ⚠️）
```bash
# 需要先安装 once_cell 依赖
# 在 Cargo.toml 添加: once_cell = "1.19"

# 需要编译 Ghidra FFI 库
cd ../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
make

# 设置库路径
export LD_LIBRARY_PATH=../ghidra/build/lib:$LD_LIBRARY_PATH

# 运行运行时验证（当前会失败，因为 FFI 未完全集成）
cargo test --features ffi-test runtime_verify::
```

### 完整验证流程（参考）
详见 [docs/VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md)

---

## 📝 注意事项

1. **版本控制**: 每完成一个类的对齐验证，需要打勾 ✅
2. **测试要求**: 所有验证函数必须有对应的单元测试
3. **文档更新**: 每次完成后更新本文档和 `alignment_mapping.md`
4. **FFI 集成**: 部分验证函数需要与 Ghidra C++ FFI 集成测试
5. **一致性声明**: 当前**无法保证**与 Ghidra 完全一致，仅完成静态对齐

---

最后更新: 2024 (自动生成)

---

## 📝 注意事项

1. **版本控制**: 每完成一个类的对齐验证，需要打勾 ✅
2. **测试要求**: 所有验证函数必须有对应的单元测试
3. **文档更新**: 每次完成后更新本文档和 `alignment_mapping.md`
4. **FFI 集成**: 部分验证函数需要与 Ghidra C++ FFI 集成测试

---

最后更新: 2024 (自动生成)