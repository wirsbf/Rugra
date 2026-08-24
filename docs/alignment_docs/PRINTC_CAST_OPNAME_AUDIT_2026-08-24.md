# C2 — PRINTC-CAST-OPNAME-LEAK-0001 实现规格（只读审计）

只读审计 Agent 产出，2026-08-24。未修改仓库任何文件、未运行 cargo/build。

## 0. 结论摘要（先读）

**根因一句话**：Rugra `src/printc.rs` 的 ZEXT/SEXT/SUBPIECE 三个发射臂（1586/1623/1669）本身已是
Ghidra `printc.cc:786/799/843` 的忠实端口，泄漏不是"缺 cast 分支"，而是**喂给判定谓词的 facing
type 状态与 Ghidra 不同**——Ghidra 由 `ActionInferTypes::buildLocaltypes → Varnode::getLocalType →
TypeOpFunc::getOutputLocal`（`typeop.cc:365`，按 op 注册 metatype 取
`getBase(size, metaout)`）保证 ZEXT/SEXT 输出至少面向 uint/int；Rugra 这条链**三层全部缺失**
（`typeop.rs` 宏的 `get_output_local` 返回对侧 varnode 的 `v_type`、`varnode.rs:1421
get_local_type` 的 op-local 合并腿是空壳、`coreaction.rs:3651 build_localtypes` 用 `vn.v_type`
播种且无 ZEXT/SEXT 臂），于是输出停在创建期默认 `undefined-N`（metatype=UNKNOWN），谓词
`isZextCast(out=UNKNOWN,…)` 拒绝 → 走合法的 `opFunc` 回退 → 裸算子名。

**关键反证（推翻 B6 §1.4 的假设）**：Ghidra C 模式**不是**"永远发 `(int)` 类 cast"。项目自带的
12.0.4 锁定 oracle 输出 `tests/golden/ghidra_httpd_1204.c:50871` 就有真值功能形态
`local_58._0_12_ = ZEXT412(1) << 0x40;`，同 golden 11185/12141 还有 `SUB81(param_1,0)`、
`SUB84(pcVar11,0)`。**若在 printc.rs 强制 cast 化，会与 oracle 直接 MISMATCH**。curl golden 的
0 计数是"该语料上类型全部收敛"的结果，不是打印器有无条件 cast 分支的证据。

**修改点计数**：printc.rs 行为改动 **0 处**（仅 2 处注释/常量卫生）；真正的实现规格落在
typeop.rs（1 处宏+3 个手写 impl）、varnode.rs（1 个函数）、coreaction.rs（1 个函数），共
**6 个修改点**（详见 §4）。注意 coreaction.rs 租约在占（B6 §3）。

## 1. Ghidra 语义：三种 op 的完整发射决策链

### 1.1 分派与命名来源

- 表达式内隐式 varnode 展开：`PrintLanguage::recurse`
  （printlanguage.cc:513-540，`defOp->getOpcode()->push(this,defOp,op)`，行 532）。
- `typeop.hh:422` `TypeOpIntZext::push → lng->opIntZext(op,readOp)`；SEXT 同型（:429 附近）；
  `typeop.hh:801` 附近 `TypeOpSubpiece::push → lng->opSubpiece(op)`。
- 功能名：`typeop.cc:1122 TypeOpIntZext::getOperatorName` =
  `name << dec << in(0)->getSize() << getOut()->getSize()` → `ZEXT48` = in0 4 字节 → out 8
  字节。SEXT 在 typeop.cc:1148，SUB 在 typeop.cc:2127（`SUB84` = 8→4）。
- op 注册 metatype（**这是后述类型保证的源头**，typeop.cc 构造器）：
  - `typeop.cc:1116 TypeOpIntZext(tlst,CPUI_INT_ZEXT,"ZEXT",TYPE_UINT,TYPE_UINT)`
  - `typeop.cc:1141 TypeOpIntSext(tlst,CPUI_INT_SEXT,"SEXT",TYPE_INT,TYPE_INT)`
  - `typeop.cc:2117 TypeOpSubpiece(tlst,CPUI_SUBPIECE,"SUB",TYPE_UNKNOWN,TYPE_UNKNOWN)`

### 1.2 INT_ZEXT（printc.cc:786-797，签名逐字摘录）

```cpp
void PrintC::opIntZext(const PcodeOp *op,const PcodeOp *readOp)
{
  if (castStrategy->isZextCast(op->getOut()->getHighTypeDefFacing(),op->getIn(0)->getHighTypeReadFacing(op))) {
    if (option_hide_exts && castStrategy->isExtensionCastImplied(op,readOp))
      opHiddenFunc(op);
    else
      opTypeCast(op);
  }
  else
    opFunc(op);
}
```

判定（cast.cc:457-469）：

```cpp
bool CastStrategyC::isZextCast(Datatype *outtype,Datatype *intype) const
{
  type_metatype metaout = outtype->getMetatype();
  if (metaout != TYPE_UINT && metaout != TYPE_INT)  return false;
  type_metatype metain = intype->getMetatype();
  if ((metain!=TYPE_UINT)&&(metain!=TYPE_BOOL))     return false;
  return true;
}
```

`isSextCast`（cast.cc:443-455）同构：metaout ∈ {UINT,INT} 且 **metain ∈ {INT,BOOL}**
（SEXT 输入须有符号；ZEXT 输入须无符号——符号不匹配时保留功能形态是**语义保持**：C cast
`(int)(uchar)c` 与符号扩展不等价）。

### 1.3 INT_SEXT（printc.cc:799-810）

与 ZEXT 逐行同构，仅换 `isSextCast`（见上）。

### 1.4 SUBPIECE（printc.cc:843-878，骨架摘录）

```cpp
void PrintC::opSubpiece(const PcodeOp *op)
{
  if (op->doesSpecialPrinting()) {            // (a) 字段提取优先
    ... isPieceStructured → explicit-vn symbol arm (853-861, pushPartialSymbol)
    ... findTruncation field arm (862-868, object_member + field atom)
    // "Fall thru to functional printing" (869)
  }
  if (castStrategy->isSubpieceCast(op->getOut()->getHighTypeDefFacing(),
                                   op->getIn(0)->getHighTypeReadFacing(op),
                                   (uint4)op->getIn(1)->getOffset()))
    opTypeCast(op);
  else
    opFunc(op);
}
```

`isSubpieceCast`（cast.cc:411-432）：

```cpp
if (offset != 0) return false;               // 截断常量必须为 0
inmeta  ∈ {INT,UINT,UNKNOWN,PTR,PARTIALSTRUCT,PARTIALUNION} else false
outmeta ∈ {INT,UINT,UNKNOWN,PTR,FLOAT}       else false
if (inmeta==TYPE_PTR) {
  if (outmeta==TYPE_PTR && outsize < insize) return true;   // far→near 指针
  if (outmeta!=TYPE_INT && outmeta!=TYPE_UINT) return false; // PTR 入只许落到整型
}
return true;
```

注意 UNKNOWN→UNKNOWN、offset=0 的 SUB 是 **cast**（输出文本 `(undefined4)x` 一类）；
PTR 入 + UNKNOWN 出是 **功能形态**（httpd golden 的 `SUB84(pcVar11,0)` 正是此类）。

### 1.5 cast 之后的三个发射器

- `printc.cc:448-464 opTypeCast`：`dt = out->getHighTypeDefFacing()`；若 `dt->isPointerToArray()
  && checkAddressOfCast(op)` → `&in0`；否则 `if(!option_nocasts){ pushOp(&typecast,op);
  pushType(dt);} pushVn(in0)` → 文本 `(ulong)x`。
- `printc.cc:474-479 opHiddenFunc`：`pushOp(&hidden)` + in0——**完全不打印**（仅保求值序），
  依赖 `option_hide_exts`（默认 true，printc.cc:1585 `resetDefaultsPrintC`）与
  `isExtensionCastImplied`（cast.cc:249-298：out 显式→false；readOp null→false；readOp 须为
  PTRADD（直接 break→true）或 ADD/SUB/MULT/DIV/AND/OR/XOR/EQ/NE/LT/LE/SLT/SLE；对侧操作数
  常量 `size > promoteSize`→false（promoteSize=`tlst->getSizeOfInt()`，cast.cc:27，x86-64=4）；
  对侧非显式→false；对侧 metatype != out metatype→false）。
- `printc.cc:424-442 opFunc`：`function_call` token + `getOperatorName(op)` 原子 + 逗号，
  `SUB44(x,0)` 的双参数逗号形态即此。

### 1.6 面向类型永不为 null 的上游保证（泄漏为 0 的真正原因）

1. **创建期默认**：`funcdata_varnode.cc:104-120 Funcdata::newVarnodeOut` —— `Datatype *ct =
   glb->types->getBase(s,TYPE_UNKNOWN); vbank.createDef(s,m,ct,op); assignHigh(vn);`
   每个 op 输出 varnode 出生即有 undefined-N 类型 + HighVariable。
2. **op-local 类型推断**：`coreaction.cc:5008-5037 ActionInferTypes::buildLocaltypes` 对每个
   varnode 取 `vn->getLocalType(needsBlock)`（**不看当前 v_type**）：
   `varnode.cc:900-940` —— typelock 直返；否则 `ct = def->outputTypeLocal()`
   （`op.hh:251 → opcode->getOutputLocal(this)`；ZEXT/SEXT 即
   `typeop.cc:365 TypeOpFunc::getOutputLocal = tlst->getBase(out->getSize(),metaout)`
   → 至少 uint8/int8），`def->stopsTypePropagation()` 时置 blockup 直返；再对每个 reader 取
   `op->inputTypeLocal(slot)`（typeop.cc:371 = `getBase(in(slot)->getSize(),metain)`）按
   `typeOrder` 取最特定；全空则 `throw LowlevelError("NULL local type")`。写入 tempType，
   传播轮次后 `coreaction.cc:5043 writeBack → vn->updateType(ct)` 落到 v_type。
3. 结果：print 时 ZEXT/SEXT 输出 facing 至少 uint/int，输入通常 uint/bool（ZEXT）或
   int/bool（SEXT）→ 谓词通过 → `(ulong)x` 或整体隐藏。golden curl 全 0、golden httpd 仅存
   x87/SIMD 等类型天然不合格的 ZEXT412/SUB81/SUB84，与此机制完全自洽。

### 1.7 四类决定性语义核对表（三个发射器）

| 项 | 引用/输出参数 | 循环边界/遍历顺序 | 计数器/累加器 | 排序/比较键 |
|---|---|---|---|---|
| opIntZext/opIntSext | `readOp` 只读传入（push 链上 reader）；无输出参数；`op` 经 pushOp/atom 只读引用 | 无循环 | 无 | isZextCast/isSextCast：先 out metatype 后 in metatype，**顺序固定** |
| opSubpiece | 同上；`getIn(1)->getOffset()` 只读 | 无循环（两 if 级联） | 无 | isSubpieceCast：offset→inmeta→outmeta→PTR 特判，级联顺序固定 |
| opTypeCast | `checkAddressOfCast(op)` 只读；RPN 栈为唯一副作用 | 无 | 无 | 无 |
| opFunc | RPN 栈副作用 | inputs `for(i=n-1;i>=0;--i)` **倒序压栈**（LIFO drain 后正序出） | 逗号数 `numInput()-1` | 无 |
| isExtensionCastImplied | outVn/readOp 只读 | `switch(readOp->code())` 单分派 | 无 | typeOrder 无；metatype 相等比较（`==`） |
| buildLocaltypes/getLocalType | `needsBlock` 为 **out bool**（Rust 需 &mut） | `descend` 遍历为插入序 | 无累加 | `0 > newct->typeOrder(*ct)` 取**最特定**（严格大于才换） |

## 2. Rust 现状与差异表（双侧行号）

### 2.1 打印侧（已对齐，勿改行为）

| Ghidra | Rust | 状态 |
|---|---|---|
| printc.cc:786-797 opIntZext | printc.rs:1586-1620（谓词 1599-1602，hidden 1606-1610，cast 1612，opFunc 1614-1619） | 忠实 |
| printc.cc:799-810 opIntSext | printc.rs:1623-1653 | 忠实 |
| printc.cc:843-878 opSubpiece | printc.rs:1669-1786（special-printing 1670-1756，谓词 1773-1778） | 忠实 |
| cast.cc:411/443/457 三谓词 | type_system/cast.rs:113/149/160（含 enum/partialenum 白名单扩展，注释已论证） | 忠实 |
| cast.cc:249 isExtensionCastImplied | printc.rs:11499-11550 | 忠实（promote 硬编码见 §4 卫生项） |
| printc.cc:448/424/474 | printc.rs:1924 rpn_op_type_cast / 1990 rpn_op_func / 2030 rpn_op_hidden_func | 忠实 |
| printc.cc:1585 option_hide_exts=true | printc.rs:668 | 一致 |
| printc.cc:2018-2029 pushPartialSymbol finalcast | printc.rs:2151 rpn_push_partial_symbol（2300-2350 有 finalcast 臂） | 忠实 |
| — | printc.rs:10856 **legacy** push_partial_symbol 缺 finalcast 臂；10849/10907 注释谎称 "Rugra has no isSubpieceCastEndian"（cast.rs:141 明明有） | 陈旧 TODO（双路径遗留） |
| — | printc.rs:5023-5036 / 7509-7525 legacy 路径对 ZEXT/SEXT 无条件打 `(uint)`/`(int)` | 非对齐替代实现（legacy 双路径；fresh 泄漏不走此路） |

全文件唯一能产生 `ZEXT/SEXT/SUB` 功能名的三个调用点是 printc.rs:1617/1650/1783
（`rpn_operator_name_ext`，printc.rs:2042）——泄漏确实出自忠实臂的 `else` 分支。

### 2.2 类型状态侧（真正的缺口，三层）

| # | Ghidra | Rust | 差异 |
|---|---|---|---|
| G1 | typeop.cc:365-368 `TypeOpFunc::getOutputLocal = tlst->getBase(out->getSize(),metaout)`；:371-374 `getInputLocal = getBase(in(slot)->getSize(),metain)` | typeop.rs:364 宏 `functional_unary_op!`：`get_output_local` 返回 **in(0) 的 v_type**、`get_input_local` 返回 **out 的 v_type**；宏根本不接收 metatype 参数（ZEXT/SEXT/SUB 注册在 typeop.rs:929-941） | **语义颠倒**：Ghidra 产新鲜基类型（uint/int），Rust 回显对侧现存类型（通常 undefined-N） |
| G2 | varnode.cc:900-940 `getLocalType`：def 的 outputTypeLocal + `stopsTypePropagation→blockup` + 全 reader 的 inputTypeLocal 按 typeOrder 合并；全空 throw | varnode.rs:1421-1428：注释写 "cc:914-939" 但函数体直接 `return self.v_type.clone()`，op-local 腿整体缺失 | 空壳 |
| G3 | coreaction.cc:5008-5037 `buildLocaltypes`：`ct = vn->getLocalType(needsBlock); vn->setTempType(ct)`（含 type-locked symbol `getExactPiece` 腿） | coreaction.rs:3651-3678：用 `vn.v_type` 播种 temp；3681 起手写 CBRANCH/compare/bool/CALL 臂，**无 ZEXT/SEXT/SUBPIECE 臂**（自认 "Mirrors the per-op local-type inference"——替代实现） | ZEXT/SEXT 输出永远得不到 uint/int 默认 |

（Rust 已有的正确底座：`Varnode::new_with_space` 默认 `v_type=default_unknown_type`，
`funcdata.rs:2004 assign_high`，`op.rs:601 stops_type_propagation`，`variable.rs:1494
HighVariable::get_type` 非 Option。）

### 2.3 泄漏形态实测（fresh vs golden）

- fresh `curl.stdout.c`：`(SUB|SEXT|ZEXT)[0-9]+` 共 **101 次**（ZEXT18×22、SUB44×18、ZEXT48×14、
  SUB84×12、SEXT14×12、SEXT48×11、SUB82×6、SEXT24×2、SEXT18×2、ZEXT24×1、SUB81×1）。
  B6 的 "31 处" = 含 SUB44/SEXT48/ZEXT48 的**行数**（31 行、43 次出现）。分布：glob_word 10 行、
  next_url 9、my_get_line 9、glob_set 8、glob_range 7、helpf 6、file2string_part_0 5、
  myprogress 3、match_url 1。
- golden `ghidra_curl_1204.c`：**0 次**；golden `ghidra_httpd_1204.c`：**3 次**（ZEXT412/SUB81/SUB84，
  §0 已引）。
- 同位置对照样本（my_get_line strlen 惯用法）：
  - fresh:664-688 … `(0 - ZEXT18(uVar200)) … SUB84(uVarb8,0) … SEXT48(SUB84(…,0)+1)`
  - golden:1329-1332 `(-(long)__dest - (ulong)CARRY1((byte)uVar7,(byte)uVar7)) … (long)puVar9 …`
  - 即 golden 把同一批 ZEXT/SUB 渲染成 `(ulong)`/`(byte)`/`(long)` cast（`CARRY1` 是 Ghidra
    合法保留的功能形态）。
- 泄漏位点静态分桶（按输出文本反推 facing type）：
  - **桶 U（UNKNOWN 出）**：ZEXT48/SEXT48 出口喂 fspec 未知的调用实参（fresh 里
    `realloc/malloc/__sprintf_chk` 实参形态畸形）→ 出 facing undefined8 → metaout 拒绝。
  - **桶 U'（UNKNOWN 入）**：`ZEXT18(uVar200)` 的 1 字节入从未被推断为 uint/bool。
  - **桶 P（PTR 入/出污染）**：`SUB84(uVarb8,0)`、`SUB44(piVar6,0)` 的入是 PTR
    （输出里可见 `(int *)`/多级指针链），出非 INT/UINT/PTR → cast.cc:428 拒绝。此桶与
    next_url 指针链（TYPE-PTRWIDTH-PTRSUB-0001 / InferTypes 不收敛，簇 C）同源。
  - **桶 D（high=None）**：`printc.rs:1599-1602` 的 `_ => false` 映射在 Ghidra 无对应物
    （§1.6-1 保证永不为 null）。静态上 Rugra 创建路径都有默认类型+assign_high，此桶预期
    非主导，但诊断脚本（§4.5）会给出实测分布。

## 3. 根因一句话

见 §0（打印臂忠实；`typeop.rs` 宏把 getOutputLocal/getInputLocal 写反成回显对侧 v_type、
`varnode.rs:1421` getLocalType 空壳、`coreaction.rs:3651` 用 v_type 播种且无 ZEXT/SEXT 臂，
三层叠加使 ZEXT/SEXT/SUBPIECE 的 facing type 停在 UNKNOWN/PTR，谓词合法拒绝后走 opFunc，
而 golden 侧同位点类型已收敛为 uint/int/bool）。

## 4. 实现规格

### 4.1 修改点清单（自底向上；file:line）

| # | 文件:行 | 改动 | 说明 |
|---|---|---|---|
| M1 | `src/typeop.rs:364`（宏）+ 929-941（ZEXT/SEXT/SUB 注册） | 宏增加 `metaout/metain` 参数并按 `typeop.cc:365/371` 实现：`get_output_local = types.get_base(op.out.size, metaout)`、`get_input_local = types.get_base(op.in(slot).size, metain)`；ZEXT=Uint/Uint、SEXT=Int/Int、SUB=Unknown/Unknown（typeop.cc:1116/1141/2117）。其余 `functional_*_op!` 用户按 typeop.cc:36-70 的 inst 表补 metatype（至少覆盖三目标 op；其余函数逐个登记，不得批量塞 Unknown 之外的臆测值） | 消除 G1。注意 typeop.rs 租约状态需查 TODO_BOARD |
| M2 | `src/varnode.rs:1421 get_local_type` | 按 varnode.cc:900-940 补全：typelock 直返 v_type；`def.output_type_local()`（经 M1 的注册表）；`stops_type_propagation()` → `*block_up = true` 直返；reader 侧 `input_type_local(slot)` 按 `type_order` 合并取最特定（严格 `0 > order` 才替换）；def 与 readers 皆空 → 对应 Ghidra `throw LowlevelError("NULL local type")`（Rust 返回 Err/None，由 M3 的 guard 保证不可达：`!is_written && has_no_descend` 跳过） | 消除 G2 |
| M3 | `src/coreaction.rs:3651 build_localtypes` | 播种改为 `vn.get_local_type(&mut needs_block)`（G3）：含 type-locked symbol `getExactPiece` 腿（curOff 计算 coreaction.cc:5018-5024）、`needs_block → set_stop_up_propagation`；删除/降级手写 compare/bool/CBRANCH 播种中与 op-local 表重复的部分（保留与 oracle 逐条对得上者；CALL 臂对应 typeop.cc:720-734 TypeOpCall::getOutputLocal，应同样下沉到 M1 注册表） | 消除 G3；**coreaction.rs 租约在占——须排队/并入 cluster C** |
| M4 | `src/printc.rs:11532` | `other_vn.get_size() > 4` → `> self.cast_strategy.promote_size`（cast.rs:63 已有字段；Ghidra cast.cc:27 `promoteSize = tlst->getSizeOfInt()`） | 卫生（对 x86-64 等价，无行为变化） |
| M5 | `src/printc.rs:10849、10907` 注释 + `src/printc.rs:10856 push_partial_symbol` | 修正陈旧注释（cast.rs:141 已有 is_subpiece_cast_endian）；legacy `push_partial_symbol` 补 printc.cc:2018-2029 allowCast/finalcast 臂（复用 cast.rs:141），或若确认 legacy 表达式路径已完全被 RPN 路径取代则在注释中登记取代关系并挂 TODO ID（双路径收敛另行立项） | 卫生/死路径对齐；不改变 RPN 主路径输出 |
| M6 | `docs/api/printc.md`、`docs/api/typeop.md`、`docs/api/varnode.md`、`docs/api/coreaction.md` + TODO_BOARD 行 | 铁律 3 同步 | 文档 |

**printc.rs 三发射臂（1586/1623/1669）与 cast.rs 三谓词：禁止任何行为改动**——它们与 oracle
一致；改了反而制造 MISMATCH（oracle httpd 的 ZEXT412/SUB84 证明功能形态是合法输出）。

### 4.2 预期 fixture（双侧观察面）

每个 fixture 用同一 P-code 输入分别跑 Ghidra oracle（`/tmp/rugra-ghidra-bfd-2.38`，重启即丢，
重建按 AGENTS「实操坑位备忘」）与 Rugra，记录**完整表达式文本**：

| ID | P-code 场景（造 IR 或 gcc 造样本） | Ghidra 期望（观察面） | Rugra 现状 | 修后 |
|---|---|---|---|---|
| F1 cast | `v8 = ZEXT v1`，v1 无其他类型来源；v8 显式（独立赋值语句） | `v8 = (ulong)v1;`（isExtensionCastImplied 对显式 out 返 false → opTypeCast） | `v8 = ZEXT18(v1);` | 同 Ghidra |
| F2 hidden | `v8 = INT_ADD(ZEXT v1, v4)`，v4 显式 int 同 metatype，v8 implied | ZEXT **整体消失**：`a + b`（opHiddenFunc） | `ZEXT18(v1) + v4` | 同 Ghidra |
| F3 语义保留 | `v4 = SEXT u1`，u1 facing uint（如 INT_AND 结果） | **功能形态** `SEXT14(u1)`（符号不匹配不得 cast 化） | 同（谓词本就 false） | 保持不变（回归守卫） |
| F4 offset 边界 | `SUB(x8, 2)`，x8/v 类型任意 | 功能形态 `SUB42(x,2)`（offset≠0 恒 false） | 同 | 保持 |
| F5 PTR 边界 | `SUB(ptr8→ptr4, 0)` | cast `(nearptr)x`；`SUB(ptr8→unknown4,0)` → 功能 `SUB84(x,0)`（对照 httpd golden 真值） | 后者同 | 保持 |
| F6 UNKNOWN/UNKNOWN | `SUB(u8→u4, 0)` 全 undefined | cast `(undefined4)x`（两 UNKNOWN 均在白名单） | `SUB84(x,0)` | cast 化 |
| F7 margin | F2 变体：对侧常量 size==promoteSize(4) vs size==8 | 4：仍可 hidden；8：`>` 严格大于 → 不隐含 → `(ulong)v1 + 0x1…` | 未按 size 分流正确性未知 | 同 Ghidra（M4 后从 promote_size 取值） |
| F8 端到端 | curl `next_url`/`my_get_line` | golden 文本 | 101 处泄漏 | 见 §4.3 验收 |

fixture 元数据按 AGENTS 记 oracle commit/arch/cspec/options/指纹；状态只能 MATCH/MISMATCH/
NO_ORACLE/UNTESTED，F3-F5 是**防过度修复**的负向守卫。

### 4.3 验收命令

```bash
cargo check --lib && cargo test --lib
cargo run --release --example curl_decompile 2>/dev/null | tee /tmp/curl.log   # 后 cp 到 result/curl_cur.c
grep -cE "(SUB|SEXT|ZEXT)[0-9]+" result/curl_cur.c        # 期望从 101 显著下降；curl 语料目标 0（golden 为 0），
                                                          # 但全局不得以 0 为不变量（httpd oracle 合法含 3）
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func next_url -v
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func my_get_line -v
python tools/audit_syntax.py result/curl_cur.c
```

printc.rs 在机制 B 白名单：即使本 TODO 实际不动 printc.rs 行为，只要 M4/M5 触碰该文件即触发
差分门禁；`defects>0` 需 `## Differential` 块逐处解释。coreaction.rs/typeop.rs/varnode.rs 非白名单，
但 M1-M3 影响可见输出，同样跑全量差分。核心算法白名单不含这些文件，但 M3 涉及主管线 Action，
建议按机制 C 找独立 reviewer。

### 4.4 风险与依赖

- M3 落在 coreaction.rs（租约在占）且与簇 C（next_url `Type propagation algorithm not
  settling`、TypeOpPtrsub downChain/STOP，交接 §3.2）同域——**建议并入簇 C 的租约排期**，
  先做 M1/M2（typeop.rs/varnode.rs 需查板确认空闲）。
- 修好 M1-M3 后，桶 P（PTR 污染）的位点仍取决于 Ptrsub 传播收敛（簇 C 另行收敛）；
  本 TODO 的判定标准是"同位点 facing type 与 oracle 同 metatype"，不是"泄漏全局归零"。
- Rugra 双打印路径（RPN 1254/legacy 8214）并存：本 TODO 不做路径收敛，但 M5 需在注释里指明
  泄漏三调用点均在 RPN 路径。

### 4.5 诊断脚本（实现 Agent 开工第一步，临时 `[DBG]` 提交前删）

在 printc.rs:1614/1648/1781 三个 else 分支临时加
`eprintln!("[DBG] leak {} out={:?} in={:?} off={}", nm, out_dt.map(|t|t.get_metatype()), in_dt.map(|t|t.get_metatype()), off)`
跑 curl_decompile，把 101 处按桶（None/Unknown/Pointer/Float/Bool/符号不匹配）计数归档进
TODO evidence——用于验证本报告的静态分桶并量化 M1-M3 各自消灭多少。

## 5. 与 PRINTC-PTRCONST-DAT-SYMBOL-0001 的串行顺序

- 两者原 scoped write-set 都占 `src/printc.rs` + `docs/api/printc.md`（同一租约，必串行）。
- PTRCONST 是**真 printc.rs 改动**（常量→指针渲染 + stringmanage 查询）；本 TODO 经审计
  **printc.rs 无行为改动需求**（仅 M4 常量引用 + M5 注释/死路径卫生）。
- 建议：**PTRCONST 先行**独占 printc.rs 租约；本 TODO 改造为"type 推断域"任务（write-set：
  typeop.rs/varnode.rs/coreaction.rs + 对应 docs），在 coreaction 租约释放或并入簇 C 后执行；
  其 printc.rs 卫生项（M4/M5）搭 PTRCONST 的 commit 顺手带上或其后一个独立小 commit，避免
  两次抢租约。若维持两 TODO 并行在板，必须显式写明 printc.rs 同一时刻单 writer。

## 6. 报告元数据

- oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`（本审计只读该目录源码）。
- fresh 输入：`/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stdout.c`
  （commit `f7b3c31`，sha256 `fc9a33ba…91d60e7`）；golden：`tests/golden/ghidra_curl_1204.c`、
  `tests/golden/ghidra_httpd_1204.c`（后者 provenance json 在同目录）。
- 引用的 Ghidra 行号均为锁定 oracle 实测（printc.cc/cast.cc/typeop.cc/typeop.hh/printlanguage.cc/
  varnode.cc/variable.cc/variable.hh/funcdata_varnode.cc/coreaction.cc/cast.hh/op.hh）。
- 引用的 Rugra 行号：src/printc.rs、src/type_system/cast.rs、src/varnode.rs、src/variable.rs、
  src/typeop.rs、src/coreaction.rs、src/funcdata.rs、src/op.rs（commit `f7b3c31` 工作区）。
