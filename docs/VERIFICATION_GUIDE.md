# Rugra-Ghidra 输出一致性验证指南

> **重要声明**: 当前 Rugra 项目**不能保证**与 Ghidra 的输出完全一致。本文档说明如何进行验证以及已知的差异。

## 📋 目录

1. [现状说明](#现状说明)
2. [验证层次](#验证层次)
3. [环境准备](#环境准备)
4. [验证步骤](#验证步骤)
5. [已知差异](#已知差异)
6. [问题排查](#问题排查)

---

## 🔴 现状说明

### 已完成
- ✅ **静态类型对齐**: 核心数据结构（Varnode, PcodeOp, Address 等）的字段对齐
- ✅ **FFI 接口**: 部分 FFI 函数用于与 Ghidra C++ 通信
- ✅ **单元测试**: 每个对齐模块都有独立的单元测试

### 未完成（关键）
- ❌ **运行时对拍**: 没有实际运行时比对 Rugra 和 Ghidra 的输出
- ❌ **端到端测试**: 没有用真实二进制文件进行完整的反编译对比
- ❌ **SSA 一致性**: Varnode 的 SSA 版本号分配算法未验证
- ❌ **优化规则顺序**: Action/Rule 的应用顺序可能不同
- ❌ **浮点数精度**: 浮点运算的精度和舍入模式未对齐
- ❌ **跳转表恢复**: 跳转表识别算法可能有差异

### 风险评估
| 组件 | 一致性风险 | 说明 |
|------|-----------|------|
| P-code 生成 | **中** | 基本操作应该一致，但 unique 空间分配可能不同 |
| 常量折叠 | **低** | 简单算术运算应该一致 |
| SSA 构造 | **高** | 版本号分配算法必须完全一致，否则后续分析全错 |
| 控制流分析 | **高** | 基本块划分、支配树计算必须一致 |
| 类型推断 | **中** | 类型传播规则可能有细微差异 |
| 代码生成 | **高** | C 代码输出格式、变量命名可能完全不同 |

---

## 📊 验证层次

### Level 1: 单元测试（已完成 ✅）

```rust
// 示例：验证 Address 对齐
#[test]
fn test_address_alignment() {
    let addr = Address::new(0x1000);
    let space = AddressSpace::Ram;
    assert!(verify_address(&addr, &space, 0x1000, 2));
}
```

**状态**: ✅ 所有静态对齐测试通过  
**限制**: 只验证数据结构，不验证算法行为

---

### Level 2: 常量求值对拍（部分完成 ⚠️）

```rust
// 运行时比对常量折叠结果
let verifier = global_verifier();
let result = verifier.verify_constant_eval(
    "add_1_2",
    PcodeOp::IntAdd,
    19,  // Ghidra INT_ADD opcode
    1, 4,
    Some((2, 4)),
    4
);

assert!(result.is_match());
```

**要求**:
1. Ghidra 必须通过 FFI 加载（需要 `ghidra_bridge` 或自定义 JNI）
2. 调用 `rugra_evaluate_constant` FFI 函数
3. 比对结果

**运行**:
```bash
# 需要先编译 Ghidra C++ FFI 库
cd ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
make

# 运行对拍测试
cd rugra
cargo test runtime_verify::tests --features ffi-test
```

---

### Level 3: P-code 生成对拍（未实现 ❌）

**测试目标**: 确保同一条机器指令生成相同的 P-code 序列

**实现方案**:
```python
# Python 脚本，使用 ghidra_bridge
import ghidra_bridge
import subprocess
import json

def compare_pcode(binary_path, address):
    # 1. Ghidra 反编译
    with ghidra_bridge.GhidraBridge() as bridge:
        bridge.remote_import("ghidra")
        currentProgram = bridge.remote_eval("currentProgram")
        
        instr = currentProgram.getListing().getInstructionAt(
            bridge.remote_eval(f"toAddr(0x{address:x})")
        )
        
        ghidra_pcodes = []
        for pcode in instr.getPcode():
            ghidra_pcodes.append({
                'opcode': pcode.getOpcode(),
                'inputs': [str(v) for v in pcode.getInputs()],
                'output': str(pcode.getOutput()) if pcode.getOutput() else None
            })
    
    # 2. Rugra 反编译
    rugra_result = subprocess.run(
        ['cargo', 'run', '--', 'pcode', binary_path, f'0x{address:x}'],
        capture_output=True, text=True
    )
    rugra_pcodes = json.loads(rugra_result.stdout)
    
    # 3. 比对
    if len(ghidra_pcodes) != len(rugra_pcodes):
        print(f"FAIL: P-code count mismatch at 0x{address:x}")
        print(f"  Ghidra: {len(ghidra_pcodes)} ops")
        print(f"  Rugra:  {len(rugra_pcodes)} ops")
        return False
    
    for i, (g, r) in enumerate(zip(ghidra_pcodes, rugra_pcodes)):
        if g['opcode'] != r['opcode']:
            print(f"FAIL: Opcode mismatch at 0x{address:x}:{i}")
            return False
    
    return True
```

**状态**: ❌ 未实现  
**优先级**: 🔴 **高** - 这是最基础的验证

---

### Level 4: SSA 构造对拍（未实现 ❌）

**关键问题**: SSA 版本号必须完全一致，否则后续所有分析都会出错

**测试方法**:
```rust
// 比对 SSA 版本号
let verifier = global_verifier();

// Rugra SSA
let rugra_program = /* 反编译结果 */;
let rugra_versions: Vec<(Address, usize)> = rugra_program
    .operations()
    .iter()
    .filter_map(|op| op.output())
    .map(|vn| (op.seqnum().addr, vn.version()))
    .collect();

// Ghidra SSA (需要通过 FFI 获取)
let ghidra_versions = get_ghidra_ssa_versions(binary, func_addr);

// 验证
let result = verifier.verify_ssa_versions(
    "test_function",
    &rugra_versions,
    &ghidra_versions
);

assert!(result.is_match(), "SSA versions must match exactly!");
```

**状态**: ❌ 未实现  
**优先级**: 🔴 **极高** - SSA 是反编译的核心

---

### Level 5: 控制流图对拍（未实现 ❌）

**测试要点**:
- 基本块划分必须完全一致
- 支配树结构必须相同
- 循环识别结果必须相同

```rust
let verifier = global_verifier();

// Rugra CFG
let rugra_blocks = rugra_analysis.cfg.blocks()
    .map(|b| (b.start_addr, b.successors().clone()))
    .collect();

// Ghidra CFG
let ghidra_blocks = get_ghidra_cfg(binary, func_addr);

let result = verifier.verify_cfg_structure(
    "test_cfg",
    &rugra_blocks,
    &ghidra_blocks
);
```

**状态**: ❌ 未实现  
**优先级**: 🔴 **高**

---

### Level 6: 端到端输出对比（未实现 ❌）

**测试目标**: 比对最终的 C 代码输出

**方法**:
```bash
#!/bin/bash
# 1. Ghidra 反编译
java -jar ghidra.jar -import test.exe -scriptPath . -postScript DecompileToC.java

# 2. Rugra 反编译
cargo run -- decompile test.exe > rugra_output.c

# 3. 规范化比对（因为格式可能不同）
diff -u \
  <(clang-format ghidra_output.c | sed 's/var_[0-9]*/VAR/g') \
  <(clang-format rugra_output.c | sed 's/var_[0-9]*/VAR/g')
```

**预期差异**:
- ✅ **可接受**: 变量命名不同（`var_1` vs `local_10`）
- ✅ **可接受**: 空白和格式不同
- ✅ **可接受**: 等价的类型表示（`int*` vs `int *`）
- ❌ **不可接受**: 控制流结构不同
- ❌ **不可接受**: 运算逻辑不同

**状态**: ❌ 未实现  
**优先级**: 🟡 **中** - 格式差异不影响语义

---

## 🛠️ 环境准备

### 1. 安装 Ghidra

```bash
# 下载 Ghidra 11.0+
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
unzip ghidra_11.0_PUBLIC_20231222.zip
```

### 2. 编译 Ghidra FFI 库

```bash
cd ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
make

# 生成 libdecomp.so (Linux) 或 decomp.dll (Windows)
```

### 3. 配置 Rugra FFI

在 `rugra/Cargo.toml` 中：
```toml
[dependencies]
once_cell = "1.19"

[features]
ffi-test = []

[build-dependencies]
cc = "1.0"
```

在 `rugra/build.rs` 中：
```rust
fn main() {
    println!("cargo:rustc-link-search=native=../ghidra/build/lib");
    println!("cargo:rustc-link-lib=dylib=decomp");
}
```

### 4. 设置测试二进制

```bash
# 使用标准测试程序
cd rugra/tests/binaries
wget https://github.com/lifting-bits/anvill-test-data/raw/master/curl/curl
```

---

## ✅ 验证步骤

### Step 1: 运行静态对齐测试

```bash
cd rugra
cargo test --lib align::
```

**预期输出**:
```
running 25 tests
test align::address::tests::test_address_alignment ... ok
test align::varnode::tests::test_varnode_alignment_success ... ok
test align::pcodeop::tests::test_verify_opcode ... ok
...
test result: ok. 25 passed; 0 failed
```

✅ **全部通过** → 进入 Step 2  
❌ **有失败** → 修复静态对齐问题

---

### Step 2: 运行常量求值对拍

```bash
# 确保 Ghidra FFI 已加载
export LD_LIBRARY_PATH=../ghidra/build/lib:$LD_LIBRARY_PATH

cargo test --features ffi-test runtime_verify::test_constant_eval
```

**预期输出**:
```
=== Verification Statistics ===
Total Tests:    100
Matches:        100 (100.00%)
Mismatches:     0
Ghidra Errors:  0
Rugra Errors:   0
```

✅ **100% 匹配** → 进入 Step 3  
⚠️ **95%+ 匹配** → 检查差异，可能可接受  
❌ **<95% 匹配** → 存在严重问题

---

### Step 3: P-code 生成对拍（需要实现）

```bash
# 使用 Python 脚本
python3 scripts/verify_pcode.py tests/binaries/curl 0x401000
```

**预期输出**:
```
Testing instruction at 0x401000: push rbp
  Ghidra: 3 P-code ops
  Rugra:  3 P-code ops
  ✓ Opcode match
  ✓ Input count match
  ✓ Output match
PASS
```

---

### Step 4: 生成对拍报告

```rust
// 在 tests/ 目录下创建集成测试
use rugra::align::runtime_verify::global_verifier;

#[test]
fn full_verification_suite() {
    let verifier = global_verifier();
    verifier.reset();
    
    // 运行所有验证测试
    run_constant_eval_tests(&verifier);
    run_pcode_generation_tests(&verifier);
    run_ssa_tests(&verifier);
    run_cfg_tests(&verifier);
    
    // 生成报告
    let report = verifier.generate_report();
    std::fs::write("verification_report.txt", report).unwrap();
    
    let stats = verifier.get_stats();
    assert!(
        stats.success_rate() >= 95.0,
        "Verification success rate too low: {:.2}%",
        stats.success_rate()
    );
}
```

---

## ⚠️ 已知差异

### 1. Unique 空间分配
**问题**: Rugra 和 Ghidra 对 temporary varnode 的 unique offset 分配可能不同

**影响**: 不影响语义，但会导致逐字节比对失败

**解决**: 使用规范化比对，忽略 unique offset 差异

---

### 2. 优化规则应用顺序
**问题**: Rugra 的 Action/Rule 应用顺序可能与 Ghidra 不同

**影响**: 最终结果应该相同，但中间状态不同

**解决**: 只比对最终输出，不比对中间状态

---

### 3. 浮点数表示
**问题**: 浮点常量的字符串表示可能不同（`1.0` vs `1.000000`）

**影响**: 仅格式差异

**解决**: 使用数值比对，允许误差范围

---

### 4. 变量命名
**问题**: Rugra 使用 `var_1`, Ghidra 使用 `local_10`

**影响**: 仅命名差异

**解决**: 规范化后比对

---

## 🐛 问题排查

### 问题: FFI 调用失败

**症状**:
```
Error: cannot load libdecomp.so
```

**解决**:
```bash
# 检查库路径
ldd target/debug/rugra | grep decomp

# 设置 LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/ghidra/build/lib:$LD_LIBRARY_PATH
```

---

### 问题: P-code 数量不匹配

**症状**:
```
FAIL: P-code count mismatch at 0x401000
  Ghidra: 3 ops
  Rugra:  5 ops
```

**排查步骤**:
1. 检查 Rugra 是否生成了额外的 NOP 操作
2. 检查 Ghidra 是否合并了某些操作
3. 查看 SLEIGH 规范是否一致

---

### 问题: SSA 版本号不匹配

**症状**:
```
SSA version mismatch at 0x401010: Rugra v2, Ghidra v3
```

**原因**: 这是**严重问题**，说明 SSA 构造算法不一致

**解决**: 需要详细调试 Heritage 算法，确保：
1. Phi 节点插入位置相同
2. 变量重命名顺序相同
3. 支配边界计算相同

---

## 📈 验证指标

### 最低要求
- ✅ 静态对齐测试: **100% 通过**
- ✅ 常量求值: **≥ 99% 一致**
- ⚠️ P-code 生成: **≥ 95% 一致**
- ❌ SSA 构造: **100% 一致**（不容妥协）
- ⚠️ CFG 结构: **≥ 98% 一致**

### 理想目标
- 🎯 所有测试: **100% 一致**
- 🎯 端到端输出: **语义等价**（格式可以不同）

---

## 🔧 持续集成

在 `.github/workflows/verify.yml` 中：
```yaml
name: Ghidra Alignment Verification

on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Ghidra
        run: |
          wget https://github.com/.../ghidra.zip
          unzip ghidra.zip
      
      - name: Build Ghidra FFI
        run: |
          cd ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
          make
      
      - name: Run verification
        run: |
          cd rugra
          cargo test --features ffi-test runtime_verify::
      
      - name: Generate report
        run: |
          cargo run --bin verify_report
          cat verification_report.txt
      
      - name: Check threshold
        run: |
          # 确保成功率 ≥ 95%
          python3 scripts/check_threshold.py verification_report.txt
```

---

## 📝 总结

### 当前能保证的
1. ✅ 数据结构字段对齐（静态）
2. ✅ 基本的常量求值一致（部分）

### 当前不能保证的
1. ❌ P-code 生成完全一致
2. ❌ SSA 构造完全一致
3. ❌ 控制流分析完全一致
4. ❌ 最终 C 代码输出一致

### 下一步工作
1. 🔴 **优先**: 实现 P-code 生成对拍测试
2. 🔴 **优先**: 实现 SSA 构造验证
3. 🟡 **重要**: 实现 CFG 结构验证
4. 🟢 **可选**: 实现端到端输出比对

---

**最后更新**: 2024  
**维护者**: Rugra Team  
**状态**: 🚧 开发中，不保证完全一致