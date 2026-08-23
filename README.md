# Rugra 🦀

**Ghidra 12.0.4 反编译器核心的 Rust 1:1 移植** —— 以"同输入同输出"为唯一对齐标准,逐函数对拍锁定 oracle。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)

---

## 这是什么

Rugra 把 Ghidra 反编译器(锁定 **12.0.4**,oracle commit `e40ed130`,114 个 `.cc` 源文件)的**核心算法管线**逐函数移植到 Rust:从 ELF 加载、x86-64 SLEIGH 提升、P-code IR、SSA/Heritage、控制流结构化到 C 伪代码输出。它不是"受 Ghidra 启发"的自研框架——每个移植函数都标注 `// Ghidra: <file>:<line>` 源位置,并要求在锁定 oracle 上以双侧差分 fixture 证明行为等价。

```
二进制解析 → 指令提升(SLEIGH x86-64) → P-code IR → SSA/Heritage → 控制流结构化 → C 代码生成
```

## 当前能力(2026-08-24,可实测)

以 curl 二进制 124 函数语料的端到端结果为准(vs Ghidra 12.0.4 golden):

| 指标 | 数值 |
|---|---|
| 反编译成功 / panic | 75 / **0** |
| 语法缺陷(defects)/ 编号错误 | **0 / 0** |
| **函数体逐字节一致** | **52/68(其中 33 个含真实控制流/调用的非平凡函数)** |
| 全量单元测试 | 1559 通过 / 2 已知(类型推断链,已登记) |
| 锁定 oracle 双侧差分 fixture | **119 个,全绿** |
| 输出确定性 | 20× 全语料运行字节一致 |

首个逐字节零差样本(`GetStr`,与 Ghidra 输出完全一致):

```c
void GetStr(char **string,char *value)
{
  char *pcVar1;
  if (*string != (char *)0x0) {
    free(*string);
  }
  if ((value != (char *)0x0) && (*value != '\0')) {
    pcVar1 = strdup(value);
    *string = pcVar1;
    return;
  }
  *string = (char *)0x0;
  return;
}
```

管线本身也经 oracle 对拍:默认 Action 树(78 节点)、三个规则池(oppool1=134 / oppool2=5 / cleanup=15 条 Rule)的注册序与 Ghidra `universalAction` 逐条一致;jumptable 守卫、常量折叠(全 opcode)、浮点位阶梯、CommentSorter 状态机、`Funcdata::clear` 生命周期等 40+ 子系统有逐字节 MATCH 的差分 fixture。

## 快速开始

```bash
cargo build --release

# 端到端:反编译 curl 全部 124 个函数,输出到 stdout
cargo run --release --example curl_decompile

# 差分门禁:与 Ghidra 12.0.4 golden 对比
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only

# 单元测试
cargo test --lib

# 任意一个锁定 oracle 差分 fixture(需 ghidra/ 子仓与 BFD,见 docs/VERIFICATION_GUIDE.md)
bash tools/run_transform_multiequal_insert_oracle.sh
```

## 差分验证方法论(项目核心)

对齐不靠"代码长得像",靠三层机器门禁:

1. **锁定 oracle**:Ghidra 源码钉在 12.0.4(`e40ed130`),fixture 记录 oracle/架构/cspec/输入五重指纹,任何漂移 fail-closed。
2. **pin-base fixture**(`tests/oracle/`,119 个):每个 fixture 双侧(锁定 Ghidra C++ 编译 vs Rust pin 快照)同输入运行,输出逐字节比对;`UNTESTED/MISMATCH/NO_ORACLE` 状态如实登记,不冒充 MATCH。
3. **端到端差分**:curl/httpd 全语料跑 `compare_ghidra.py`,defects/numbering 必须为零且逐处归因。

核心算法模块的改动另需独立 Agent 交叉复核(机制 C):复核者必须亲自读 oracle 源码重推语义,历史上拦截过多次"fixture 全绿但语义前提错误"的交付。

## 仓库结构

```
src/                 # ~95 个模块,1:1 对应 Ghidra .cc(op/varnode/funcdata/heritage/
                     #   blockaction/jumptable/varmap/merge/printc/ruleaction/...)
ghidra/              # 锁定 oracle 源码(子仓,HEAD 钉在 e40ed130)
sleigh_specs/        # x86-64 .sla/.pspec/.cspec(SLEIGH 处理器规格)
examples/            # curl_decompile / httpd_decompile 等端到端入口
tests/oracle/        # 119 个 pin-base 双侧差分 fixture
tools/               # compare_ghidra / audit_syntax / stage_bisect / oracle runner 等
docs/
  TODO_BOARD.md      # 活动任务看板(带 owner/write-set/验收证据)
  api/               # 与 src/ 1:1 的 API 参考
  alignment_docs/    # 管线阶段树、审计报告、对齐硬规则
  alignment_audit/   # 6 份跨模块差距审计(jumptable/coreaction/condexe/ruleaction/fspec/flow)
ALIGNMENT_ROADMAP.md # 模块级 L1/L2/L3 状态账本
AGENTS.md            # 开发铁律与门禁机制(贡献必读)
```

## 已知差距(诚实战报)

全局完成度未证明;尚未对齐的部分集中在:

- **流边界/尾调用**(shared-return、PLT thunk 转换)——多个函数膨胀/产出不足的共同根因,已在途
- **fspec 参数模型**:忠实的 `fillin_map` 尚未接入主管线(生产走 SysV stub)
- **类型传播链**(TypeOp 派发 → Varnode 局部类型 → ActionInferTypes)未打通
- switch 恢复依赖的 `truncatedFlow` partial clone 缺失;子函数内联为 stub

全部缺口以稳定 ID 登记在看板,附双侧 file:line 根因——差距是图纸化的,不是模糊的。

## 参与开发

读 `AGENTS.md`(对齐铁律:Ghidra 源码先行、机制 A-F 门禁、原子提交纪律)。任何 `src/*.rs` 修改前必须在当轮完整阅读对应 Ghidra 函数体;提交钩子强制校验 `// Ghidra:` 注释引用与对齐证据块。

## License

Apache-2.0
