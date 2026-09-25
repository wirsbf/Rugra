# drillfmt

> 对应 `src/drillfmt.rs`。RUGRA-GLUE 模块:Ghidra 无单一对应物;这是
> stage-bisect v2 drill 发射器(Lane AA)专用的 oracle 原文格式化层,把
> Rugra IR 渲染成 Ghidra console debug 原语的精确文本拼写,只读、不回灌
> 管线。激活条件:`RUGRA_STAGE_DRILL=1`(经 `drillobserve::is_enabled`)。

## 2026-09-22: 建模块(Lane AA, v2 drill emitter)

- `seqnum_raw(pc, uniq)`:`<pc.printRaw>:<uniq-hex>` — address.cc:32-38 +
  AddrSpace::printRaw(space.cc:206-221)留下的 hex 流状态使 uniq 也按
  十六进制输出;地址宽度按 8/6/4 字节动态收缩(space.cc:208-215)。
- `DrillFmt::varnode_raw`:varnode.cc:711-756 printRawNoMarkup/printRaw 全
  语义 — 寄存器名(含 `+off` 子寄存器后缀,xref 反查 point.offset/size)、
  否则 `<shortcut><offset>`(`#`/`u`/`s`/`r` 按空间)、`expect!=size` 时
  `:size`、`(i)`、`(<def-seqnum>)`(无前导空格)、`(free)`。
- `DrillFmt::op_print_debug`:op.cc:376-385 — `<seqnum>: ` + dead/unattached
  `**` 或 printRaw。
- `DrillFmt::op_raw`:typeop.cc 各 TypeOp 结构形式 — binary/unary/func、
  copy、load/store(空间名)、call/callind、return、branch/cbranch
  (Block_<i>:<start> printShortHeader)、multiequal(` ? ` 连接)、
  indirect(`[]`/`[create]`)、ptradd(`(*i2)`)、ptrsub(`->`)、
  subpiece(动态 `SUB<in><out>`,typeop.cc:2127-2135);operator 名取
  Ghidra ctor 名 + getOperatorName 覆盖(float 系 `f+` 等,与
  src/typeop.rs 注册名一致)。
- 已登记格式缺口(不影响本语料,不构成管线差异):
  - SB-DRILL-RAM-SHORTCUT:ram 空间 varnode 的 shortcut 在 next_url 语料
    中未出现,暂按 `'0'` 输出,未与 oracle 对拍。
  - SB-DRILL-FSPEC-NAME:CALL 目标恒 `ffunc_<addr>`;oracle 经 FspecSpace
    打印被调函数真名,命名 callee 会差(本语料被调者全是无名 PLT stub,
    双侧一致)。
  - iop varnode:经 drillobserve 指针注册表解析为被引 op 的 SeqNum
    (op.cc:41-47 非分支形式);被引 op 已销毁时退化为原始偏移。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
