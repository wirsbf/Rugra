# Ghidra ↔ Rugra 函数级对齐清单 — 索引

**用途**:每个 Ghidra `.cc` 文件的每个函数,对照 Rugra 实现,逐个核对四类决定性语义后打勾。

**图例**:✅ 已对齐 | ❌ 未对齐(标 Ghidra 行 + Rugra 行 + 缺口) | ⚠️ 部分对齐 | 🔍 待核对 | ➖ 不移植/替代实现

**核对流程(铁律 1.2)**:
1. 本 session 内 Read 该 Ghidra 函数全貌(不止签名行)
2. 逐条核对四类决定性语义(引用参数 / 遍历顺序 / 计数器 / 比较键)
3. Read Rugra 对应函数
4. 比对,在表格更新状态
5. ❌ 的函数:重写 Rugra 对齐 Ghidra,改状态为 ✅

## 已完成清单文件

| 优先级 | 文件 | 文档 | 函数数 |
|---|---|---|---|
| P0 地基 | address.cc / space.cc | `FUNC_address_space.md` | ~85 |
| P0 地基 | varnode.cc / op.cc | `FUNC_varnode_op.md` | ~135 |
| P0 地基 | funcdata_op.cc / funcdata.cc / funcdata_varnode.cc / funcdata_block.cc | `FUNC_funcdata.md` | ~185 |
| P0 地基 | block.cc | `FUNC_block.md` | ~120 |
| P1 算法 | heritage.cc / merge.cc / varmap.cc | `FUNC_heritage_merge_varmap.md` | ~170 |
| P1 算法 | blockaction.cc / jumptable.cc / condexe.cc | `FUNC_blockaction_jumptable_condexe.md` | ~190 |
| P2 管线 | action.cc / coreaction.cc / ruleaction.cc | `FUNC_actions_rules.md` | ~465 |
| P3 输出 | type.cc / typeop.cc / cast.cc / printc.cc / prettyprint.cc / printlanguage.cc | `FUNC_type_print.md` | ~620 |
| P1 算法 | cover.cc / rangeutil.cc | `FUNC_cover_rangeutil.md` | ~85 |

## 总计
~2055 个 Ghidra 函数需逐个核对。

## 当前最紧急
**funcdata_op.cc::opSetInput** — 已重写对齐 Ghidra cc:104-125(early-out / const dedup / opUnsetInput / addDescend+setInput),但 `&mut self` 签名导致 608 调用者编译错误。下一步:逐个修调用者,让 fd 在调用点可变借用,不绕过 const dedup。

详细清单见各 FUNC_*.md 文件。
