# constseq 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 1004行 (`constseq.cc`) / Rugra: 805行 (`src/constseq.rs`) / 比率: 80%

## 设计说明（重要架构偏差）
Ghidra 用三个类 `ArraySequence` / `StringSequence` / `HeapSequence` 分别承载 COPY 路径与 STORE 路径的逻辑；Rugra 将三者折叠为单一 `ArraySequence` 类，`StringSequence`/`HeapSequence` 退化为仅含 `base: ArraySequence` 的空 wrapper，原属 `StringSequence::*` / `HeapSequence::*` 的逻辑被搬进 `ArraySequence::*`（如 `check_interference`、`build_string_copy`、`transform`）或搬进两个 Rule 的 `apply_op` 内联体。本审计按"语义是否被覆盖"而非"类是否对应"来判定对齐。

## 已对齐函数 (19个)

### WriteNode
- `WriteNode::new` — Ghidra: constseq.hh:39 `WriteNode::WriteNode` (构造) ✅

### ArraySequence (含从 StringSequence/HeapSequence 折合的逻辑)
- `ArraySequence::is_valid` — Ghidra: constseq.cc:28 (推断; `isValid`) ✅
- `ArraySequence::interfere_between` — Ghidra: constseq.cc:42 `ArraySequence::interfereBetween` ✅
- `ArraySequence::check_interference` — Ghidra: constseq.cc:62 `ArraySequence::checkInterference` ✅ (并吸收了 `StringSequence::collectCopyOps` 的部分逻辑)
- `ArraySequence::new` — Ghidra: constseq.hh:56 `ArraySequence::ArraySequence` ✅
- `ArraySequence::sort_ops` — Ghidra: 内联 `WriteNode::operator<` 的比较语义 (constseq.hh:41) ✅ (非同名实现)
- `ArraySequence::form_byte_array` — Ghidra: constseq.cc:108 `ArraySequence::formByteArray` ✅
- `ArraySequence::is_valid_string` — Ghidra: 内联 (constseq.cc 内 byte_array 校验) ✅
- `ArraySequence::get_string` — Ghidra: 内联 (constseq.cc 内取串) ✅
- `ArraySequence::select_string_copy_function` — Ghidra: constseq.cc:161 `ArraySequence::selectStringCopyFunction` ✅
- `ArraySequence::build_string_copy` — Ghidra: constseq.cc:347/698 `StringSequence::buildStringCopy` + `HeapSequence::buildStringCopy` (合并) ✅
- `ArraySequence::transform` — Ghidra: constseq.cc:453 `StringSequence::transform` + constseq.cc:927 `HeapSequence::transform` (合并) ✅ (同时吸收了 `removeCopyOps` @ constseq.cc:415 与 `removeStoreOps` @ constseq.cc:871 的 op 销毁逻辑)

### RuleStringCopy (实现 Rule trait)
- `RuleStringCopy::new` — Ghidra: constseq.hh:121 `RuleStringCopy::RuleStringCopy` ✅
- `RuleStringCopy::apply_op` — Ghidra: constseq.cc:954 `RuleStringCopy::applyOp` ✅
- `RuleStringCopy::get_name` — Ghidra: `Rule::getName` (基类) ✅
- `RuleStringCopy::get_opcodes` — Ghidra: constseq.cc:942 `RuleStringCopy::getOpList` ✅

### RuleStringStore (实现 Rule trait)
- `RuleStringStore::new` — Ghidra: constseq.hh:132 `RuleStringStore::RuleStringStore` ✅
- `RuleStringStore::apply_op` — Ghidra: constseq.cc:986 `RuleStringStore::applyOp` ✅ (并吸收了 `HeapSequence::collectStoreOps` @ constseq.cc:663 的简化收集逻辑)
- `RuleStringStore::get_name` — Ghidra: `Rule::getName` (基类) ✅
- `RuleStringStore::get_opcodes` — Ghidra: constseq.cc:974 `RuleStringStore::getOpList` ✅
- `RuleStringStore::ptr_shares_base` — Ghidra: constseq.cc:465 `HeapSequence::findBasePointer` (简化版) ✅

## 缺失函数 (14个)

### StringSequence — 缺失 1 个
- `StringSequence::removeForward` — Ghidra: constseq.cc:383 — 优先级: 中 — 从写集合中移除一个节点并维护 xref 反向索引（用于 `removeCopyOps` 的辅助）。Rugra 直接整批销毁 move_ops，未做单节点前向清理，对当前 transform 路径无影响，但与 Ghidra 的细粒度维护不同。

### HeapSequence — 缺失 11 个（多数为复杂地址分析逻辑）
- `HeapSequence::findBasePointer` — Ghidra: constseq.cc:465 — 优先级: **高** — 完整的基指针识别（处理 PTRADD/COPY/MULT/SEGMENTOP 等地址计算链）。Rugra `ptr_shares_base` 仅做 PTRADD/COPY 两层回溯，未覆盖 MULT/SEGMENTOP/ADD 常量分量，漏判风险高。
- `HeapSequence::findDuplicateBases` — Ghidra: constseq.cc:486 — 优先级: **高** — 发现指向同一区域的多个不同基指针（别名基址）。Rugra 完全缺失，会导致多基址的字符串序列无法识别。
- `HeapSequence::findInitialStores` — Ghidra: constseq.cc:544 — 优先级: 中 — 从根 STORE 出发定位初始 store 集合（含对齐/重叠剔除）。Rugra 用 `applyOp` 内联的简化收集替代，未做重叠剔除。
- `HeapSequence::calcAddElements` — Ghidra: constseq.cc:583 — 优先级: 中 — 递归计算 PTRADD/INT_ADD 地址表达式中的元素个数与非常量分量。Rugra 缺失，无法精确推断序列长度。
- `HeapSequence::calcPtraddOffset` — Ghidra: constseq.cc:604 — 优先级: 中 — 计算 PTRADD 相对基址的偏移。Rugra 缺失。
- `HeapSequence::setsEqual` — Ghidra: constseq.cc:636 — 优先级: 低 — 比较两个 Varnode 集合是否相等（去重用）。
- `HeapSequence::testValue` — Ghidra: constseq.cc:648 — 优先级: 中 — 测试一个 STORE 是否写入指定 char 值（用于配对去重）。
- `HeapSequence::collectStoreOps` — Ghidra: constseq.cc:663 — 优先级: **高** — 完整的 store 收集算法（处理间接对、重复基址、跨步）。Rugra 仅做同块同基址的线性扫描，缺失间接对与去重。
- `HeapSequence::gatherIndirectPairs` — Ghidra: constseq.cc:770 — 优先级: 中 — 收集 STORE 间的间接配对（用于合并跨越 CALL/STORE 的串写）。
- `HeapSequence::deduplicatePairs` — Ghidra: constseq.cc:827 — 优先级: 中 — 对间接配对去重，确保每个元素只写一次。
- `HeapSequence::removeStoreOps` — Ghidra: constseq.cc:871 — 优先级: 低 — 销毁 store 序列（含递归销毁地址算子）。Rugra 由 `transform` 内的 `op_destroy_recursive` 替代，语义等价但无独立入口。

### WriteNode — 缺失 1 个
- `WriteNode::operator<` — Ghidra: constseq.hh:41 (内联) — 优先级: 低 — 按 SeqNum order 排序的比较算子。Rugra 用 `ArraySequence::sort_ops` 内联比较替代。

### StringSequence/HeapSequence 构造 — 缺失 2 个
- `StringSequence::StringSequence` — Ghidra: constseq.hh:77 — 优先级: 低 — 构造（需 SymbolEntry，Rugra 暂无 Symbol 基础设施）。
- `HeapSequence::HeapSequence` — Ghidra: constseq.hh:115 — 优先级: 低 — 构造。

## 高优先级缺失清单 (4个)
1. `HeapSequence::findBasePointer` (constseq.cc:465) — 基址识别不全，漏判别名基址
2. `HeapSequence::findDuplicateBases` (constseq.cc:486) — 多基址场景完全不支持
3. `HeapSequence::collectStoreOps` (constseq.cc:663) — store 收集过于简化，缺少间接对处理
4. `StringSequence::collectCopyOps` 的完整形态 — Rugra `check_interference` 仅覆盖线性同块场景

## 说明
- `StringSequence` / `HeapSequence` 两个类在 Rugra 中为空 wrapper（仅 `base: ArraySequence`），其方法被折叠进 `ArraySequence` 或 Rule 的 `apply_op`。这是明确的架构决策（模块头注释已声明"skeleton"），但导致 13 个 HeapSequence 方法无独立对应入口。
- 依赖未实现的基础设施：完整的 `HeapSequence` 路径需要 `Symbol`/`SymbolEntry`、`Scope`、间接配对分析等，Rugra 目前未具备。
