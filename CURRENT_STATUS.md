# Rugra 当前状态报告

**日期**: 2024  
**版本**: 0.1.0 (开发中)  
**状态**: 🚧 **不能保证与 Ghidra 输出一致**

---

## 🎯 核心问题回答

### ❓ "能保证输出和 Ghidra 的完全一致吗？"

**答案**: ❌ **不能保证**

**原因**:
1. 只完成了**静态类型对齐**，没有运行时验证
2. 没有实际的端到端测试
3. SSA 构造算法未经验证（这是最关键的）
4. 控制流分析、优化规则应用顺序可能不同
5. 缺少与 Ghidra 的实时对拍测试

---

## ✅ 已完成的工作

### 1. 静态类型对齐 (7个核心类)

#### ✅ `Address` 和 `SeqNum` (`src/align/address.rs`)
- 验证函数: `verify_address()`, `verify_seqnum()`
- 单元测试: ✅ 全部通过
- 对齐内容:
  - SpaceID 映射
  - Offset 比对
  - Order/Time 字段

#### ✅ `Varnode` (`src/align/varnode.rs`)
- 验证函数: `verify_varnode()`, `verify_varnode_list()`
- 单元测试: ✅ 全部通过
- 对齐内容:
  - AddressSpace 枚举映射
  - Offset, Size 字段
  - SSA version 字段（但未验证算法）

#### ✅ `PcodeOp` / `PcodeOperation` (`src/align/pcodeop.rs`)
- 验证函数: `verify_opcode()`, `verify_operation()`
- 单元测试: ✅ 全部通过
- 对齐内容:
  - 完整的 OpCode 映射表（75+ opcodes）
  - Input/Output Varnode 列表
  - SeqNum 关联

#### ✅ `DataType` (`src/align/datatype.rs`)
- 验证函数: `verify_datatype()`, `verify_struct_layout()`
- 单元测试: ✅ 全部通过
- 对齐内容:
  - 基本类型大小
  - Metatype (ptr, array, struct)
  - Struct 字段布局

#### ✅ `Range` / `RangeList` (`src/align/range.rs`)
- 验证函数: `verify_range()`, `verify_range_list()`
- 单元测试: ✅ 全部通过
- 对齐内容:
  - 地址范围表示
  - contains(), overlaps() 逻辑
  - 范围合并算法

### 2. 运行时验证框架 (`src/align/runtime_verify.rs`)

#### ✅ 已创建的基础设施
- `RuntimeVerifier` 类
- `VerifyResult` 枚举
- `VerifyStats` 统计
- `MismatchRecord` 差异记录

#### ⚠️ 已定义但未实现的验证方法
- `verify_constant_eval()` - 常量求值对拍
- `verify_pcode_generation()` - P-code 生成对拍
- `verify_ssa_versions()` - SSA 版本号验证
- `verify_cfg_structure()` - 控制流图验证

**问题**: 这些方法调用了 Ghidra FFI，但 FFI 没有完全集成和测试。

---

## ❌ 未完成的关键工作

### 1. 运行时对拍测试 (优先级: 🔴 极高)

#### 问题
- FFI 函数存在（`rugra_evaluate_constant` 等），但没有实际调用
- 没有集成测试验证 FFI 是否正确工作
- 没有用真实数据测试

#### 需要做什么
```bash
# 1. 编译 Ghidra FFI 库
cd ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
make

# 2. 添加依赖到 Cargo.toml
# once_cell = "1.19"

# 3. 配置 build.rs 链接 Ghidra 库

# 4. 编写集成测试
cargo test --features ffi-test runtime_verify::
```

#### 预期结果
```
=== Verification Statistics ===
Total Tests:    1000
Matches:        950 (95.00%)   # 目标: ≥95%
Mismatches:     50
```

---

### 2. P-code 生成一致性 (优先级: 🔴 极高)

#### 问题
- Rugra 的 P-code 生成器基于自己的实现
- 没有验证是否与 Ghidra 的 SLEIGH 输出一致
- Unique 空间分配可能不同

#### 测试方法
```python
# Python 脚本使用 ghidra_bridge
def test_pcode_at_address(binary, addr):
    ghidra_ops = get_ghidra_pcode(binary, addr)
    rugra_ops = get_rugra_pcode(binary, addr)
    
    assert len(ghidra_ops) == len(rugra_ops)
    for g_op, r_op in zip(ghidra_ops, rugra_ops):
        assert g_op.opcode == r_op.opcode
        assert g_op.inputs == r_op.inputs
```

#### 风险
- **中**: 基本操作应该一致
- **高**: Unique 空间 offset 可能不同（但不影响语义）

---

### 3. SSA 构造一致性 (优先级: 🔴 **极高**)

#### 问题
**这是最关键的问题！** SSA 版本号如果不一致，后续所有分析都会错误。

#### 为什么重要
```rust
// 如果 Ghidra 生成:
// v1 = LOAD(stack[0])
// v2 = ADD(v1, 10)
// STORE(stack[0], v2)

// 但 Rugra 生成:
// v1 = LOAD(stack[0])
// v3 = ADD(v1, 10)  // 版本号错误！
// STORE(stack[0], v3)

// 后续的数据流分析、类型推断全部错误！
```

#### 需要验证
1. Phi 节点插入位置完全相同
2. 支配边界计算完全相同
3. 变量重命名顺序完全相同
4. SSA 版本号分配完全相同

#### 测试方法
```rust
let result = verifier.verify_ssa_versions(
    "test_func",
    &rugra_ssa_map,
    &ghidra_ssa_map
);
assert!(result.is_match(), "SSA MUST be 100% identical!");
```

#### 容忍度
- **0%** - 必须 100% 一致，不容妥协

---

### 4. 控制流图一致性 (优先级: 🔴 高)

#### 问题
- 基本块划分算法可能不同
- 支配树计算可能有差异
- 循环识别结果可能不同

#### 影响
- 基本块不同 → 数据流分析错误
- 支配树不同 → SSA 构造错误
- 循环不同 → 优化结果不同

#### 需要验证
```rust
// 基本块起始地址必须完全相同
verify_cfg_structure(
    &[(0x1000, vec![0x1010, 0x1020])],  // Rugra
    &[(0x1000, vec![0x1010, 0x1020])]   // Ghidra
);
```

---

### 5. 端到端输出验证 (优先级: 🟡 中)

#### 问题
- 最终 C 代码输出格式肯定不同
- 变量命名不同
- 但**语义应该等价**

#### 可接受的差异
- ✅ 变量名: `var_1` vs `local_10`
- ✅ 格式: 空白、括号位置
- ✅ 类型表示: `int*` vs `int *`

#### 不可接受的差异
- ❌ 控制流结构不同
- ❌ 运算逻辑不同
- ❌ 函数调用参数不同

---

## 📊 当前可靠性评估

| 组件 | 静态对齐 | 运行时验证 | 可靠性评估 | 风险 |
|------|---------|-----------|-----------|------|
| 数据结构 (Address, Varnode) | ✅ 100% | ❌ 0% | 🟢 高 | 低 |
| OpCode 映射 | ✅ 100% | ❌ 0% | 🟢 高 | 低 |
| 常量求值 | ✅ 静态 | ❌ 未测 | 🟡 中 | 中 |
| P-code 生成 | ✅ 静态 | ❌ 未测 | 🟡 中 | 中 |
| **SSA 构造** | ✅ 静态 | ❌ **未测** | 🔴 **未知** | **极高** |
| 控制流分析 | ⚠️ 部分 | ❌ 未测 | 🔴 未知 | 高 |
| 类型推断 | ⚠️ 部分 | ❌ 未测 | 🟡 中 | 中 |
| 优化规则 | ⚠️ 部分 | ❌ 未测 | 🟡 中 | 中 |
| C 代码生成 | ❌ 未对齐 | ❌ 未测 | 🟡 中 | 中 |

### 综合评估
- **静态对齐**: ✅ 40% 完成（7/50+ 类）
- **运行时验证**: ❌ 0% 完成
- **端到端一致性**: ❌ **无法保证**
- **生产可用性**: ❌ **不推荐**

---

## 🚨 关键风险

### 1. SSA 版本号不一致 (风险等级: 🔴 极高)
**后果**: 后续所有分析都会错误  
**缓解**: 必须实现 SSA 验证测试

### 2. 控制流结构不同 (风险等级: 🔴 高)
**后果**: 基本块划分错误 → 数据流分析错误  
**缓解**: 实现 CFG 对拍测试

### 3. 优化规则应用顺序不同 (风险等级: 🟡 中)
**后果**: 中间结果不同，但最终结果可能相同  
**缓解**: 只比对最终输出

### 4. 浮点数精度差异 (风险等级: 🟢 低)
**后果**: 浮点常量表示不同  
**缓解**: 使用数值比对

---

## 📋 下一步工作清单

### 立即执行 (本周)
- [ ] 添加 `once_cell` 到 `Cargo.toml`
- [ ] 配置 `build.rs` 链接 Ghidra FFI 库
- [ ] 编写 1 个常量求值对拍测试并运行
- [ ] 验证 FFI 调用是否工作

### 短期 (本月)
- [ ] 实现 P-code 生成对拍测试（至少 100 条指令）
- [ ] 实现 SSA 版本号验证测试
- [ ] 实现基本块划分验证测试
- [ ] 生成第一份对拍报告

### 中期 (下季度)
- [ ] 完成所有核心类的静态对齐（50+ 类）
- [ ] 实现完整的运行时验证套件
- [ ] 达到 95% 以上的对拍成功率
- [ ] 用 curl 等真实程序进行端到端测试

### 长期 (未来)
- [ ] 实现所有 Ghidra Action/Rule
- [ ] 100% 对拍成功率
- [ ] 生产环境可用

---

## 🎯 成功标准

### 最低可接受标准
- ✅ 静态对齐: 100% 核心类完成
- ✅ 常量求值: ≥ 99% 一致
- ✅ P-code 生成: ≥ 95% 一致
- ✅ **SSA 构造: 100% 一致**（不容妥协）
- ✅ CFG 结构: ≥ 98% 一致
- ⚠️ 端到端输出: 语义等价（格式可以不同）

### 理想标准
- 🎯 所有测试: 100% 一致
- 🎯 端到端输出: 完全一致

---

## 📞 联系方式

如果你想要使用 Rugra：

1. **如果只是学习/研究**: ✅ 可以使用，但注意限制
2. **如果用于生产环境**: ❌ 不推荐，输出不可靠
3. **如果需要与 Ghidra 一致的输出**: ❌ 当前无法保证

如果你想要贡献：
- 🔴 **最需要**: 实现运行时验证测试
- 🔴 **最需要**: SSA 构造算法验证
- 🟡 **重要**: 更多核心类的静态对齐

---

## 📚 相关文档

- [验证指南](docs/VERIFICATION_GUIDE.md) - 详细的验证步骤
- [对齐进度](ALIGNMENT_PROGRESS.md) - 详细进度跟踪
- [对齐映射](docs/alignment_docs/alignment_mapping.md) - Rugra-Ghidra 映射表

---

**最后更新**: 2024  
**状态**: 🚧 开发中  
**可靠性**: ⚠️ 实验性质，不保证一致性  
**建议**: 在使用前完成运行时验证