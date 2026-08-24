# R4 独立复核报告 — TYPEFACTORY-EXACTPIECE-CALLERS-0001

- 复核对象: worktree `/home/wirs/.cache/rugra-wt-myfwrite-splitdatatype` 分支 `agent/myfwrite-splitdatatype`
  提交 `26116cc`（production）+ `57d4c0f`（re-pin），基线 `cad41c2`
- 复核 Agent: 机制 C 独立复核（不采信实现者声明，Ghidra 原文与双侧产物全部自查自跑）
- 复核时间: 2026-08-25（锁定 oracle `e40ed13014025f82488b1f8f7bca566894ac376b`，HEAD 实测一致）
- 结论: **APPROVE**

## 0. 独立复现（最强证据，非采信声明）

本机工具链 sha 与 runner pin 完全匹配（cargo=131c52b3…/rustc=060916a7…/g++=f04191f6…），
复核 Agent 亲自执行 `tools/run_exactpiece_callers_oracle.sh`（worktree HEAD，退出码 0）：

```
metadata_pins_ok
records=20 bilateral=byte-identical
exactpiece_callers_1204: MATCH records=20 entry=8 finalize=5 sync=5 rule=2
oracle=e40ed13014025f82488b1f8f7bca566894ac376b candidate=26116cc4ef85675979dc38de603e1b5925b5cf3b
```

- oracle 侧 stdout sha256 实测 = `11dc00e9bc1df5b9102e7500f9671ec3be795008f9747e8ace085060c65fcdf8`，
  与 metadata pin 逐字节一致；20 行与 `expected_lines` 逐行相等；`ghidra.stderr` 0 字节。
- Rust 侧从 `26116cc` 的 git archive 离线锁定构建，与 C++ 侧 `diff -u` byte-identical（runner 内部强制）。
- stderr 空不是声明而是 runner 硬门禁：`[[ -s ghidra.stderr ]]` / `[[ -s rugra.stderr ]]` 非空即失败（:343/:426）。

## 1. 四调用点逐行核对（`git diff cad41c2..26116cc -- src/`）

### 1.1 variable.rs `finalize_datatype`（src/variable.rs:670，改后 :671-696）

- Ghidra 原文（variable.cc:551-566，逐行自读）:
  `void HighVariable::finalizeDatatype(TypeFactory *typeFactory)`，:554 symbol null 早退；
  :555 `cur = symbol->getType()`；:556-558 `off<0 → 0`；:559 `sz = inst[0]->getSize()`；
  :560 `typeFactory->getExactPiece(cur, off, sz)`；:561-562 结果 null/TYPE_UNKNOWN 早退；
  :563-565 `type=tp; stripType(); highflags|=type_finalized`。
- Rugra 改动: 签名增加 `&mut TypeFactory`；旧本地近似（`get_sub_type` + 无 partial 构造 + 整型回退）
  全部删除，替换为 `type_factory.get_exact_piece(cur, off as i64, sz)`；`Some(t) if metatype != Unknown`
  守卫 + None/Unknown 早退与 cc:561-562 一致；`v_type.set(tp)` 保留 canonical Arc。
- coreaction.rs 侧: `type_factory = fd.get_arch().and_then(|arch| arch.types.clone())` 在
  link_symbols 循环前捕获一次（coreaction.rs:4624），addr-tied 分支传入（:4713-4723），
  与 Ghidra coreaction.cc:2946 `TypeFactory *typeFactory = data.getArch()->types` 循环外一次捕获、
  :2972 `high->finalizeDatatype(typeFactory)` 传递模型一致。

### 1.2 database.rs `get_sized_type` / `update_type`（src/database.rs:310/:337）

- Ghidra 原文（database.cc:151-162，逐行自读）: :156-159 `isDynamic() ? off=offset :
  off=(int4)(inaddr-addr)+offset`；:160 `cur=symbol->getType()`；:161
  `return symbol->getScope()->getArch()->types->getExactPiece(cur, off, sz)`。
- Rugra: is_dynamic 分支 `self.offset`（:315-317）与静态分支
  `((inaddr-addr) as i64 wrapping) as i32 + self.offset`（i32 截断同 C++ `(int4)`）逐条对齐；
  旧的 `get_sub_type` 手工整型/字段匹配 fallback 删除，委托
  `type_factory.get_exact_piece(dt, off as i64, size)`（:324）。
- 架构差异如实文档化: Rugra Symbol 不持 Scope owner，工厂显式传入（doc comment 注明），
  与 Ghidra entry→scope→arch 链到达**同一** Architecture 工厂等价（fixture 验证同一 factory_arc）。
- `usize::try_from(sz).ok()?` 负值 fail-closed: oracle 域外（所有 Ghidra 调用方传 `vn->getSize()` 正数），
  commit evidence 已声明。
- `update_type`（database.cc:135-144）: TYPELOCK 门禁 + 委托 get_sized_type 结构不变，仅工厂透传。

### 1.3 funcdata.rs `sync_varnodes_with_symbols`（src/funcdata.rs:2542 起）

- Ghidra 原文（funcdata_varnode.cc:938-989 + 1048-1095，逐行自读）: :955
  `entry->getSize() >= vnexemplar->getSize()` 分支；:956-960 `ct = entry->getSizedType(...)` 且
  TYPE_UNKNOWN 置 null；:962-969 小符号 `fl &= ~(typelock|namelock)`；ct 消费在
  syncVarnodesWithSymbol :1093-1095 `vn->updateType(ct)`。
- Rugra: `exact_piece_arc_sub_type` 本地下钻函数（无 partial 构造、丢 canonical identity）整体删除，
  全仓 grep 零残留；`local_symbol_sized_type` 简化为工厂委托（funcdata.rs:262-272）；
  `type_factory = self.get_arch().and_then(|arch| arch.types.clone())` 一次捕获（:2557），
  per-varnode 写锁内调用（:2611-2621），`sym.size as i64 >= size` / UNKNOWN 丢弃 / 小符号清位
  与 cc:955/958-959/967 逐条一致；ct 经 `vn_w.update_type(ct.clone())`（:2754）消费同 cc:1093-1095。
- 工厂缺失时类型投影跳过、flag 同步照常——fail-closed 声明与代码一致（metadata 登记 UNTESTED，见 §5）。

### 1.4 ruleaction.rs `RulePieceStructure::apply_op` leaf（src/ruleaction.rs:12041 起）

- Ghidra 原文（ruleaction.cc:7607-7700，逐行自读）: :7643 `anyAddrTied` or-累加；:7645
  `for(i=0;i<stack.size();++i)`；:7650 `vn->getAddr()==addr` 就地/替换分界；:7665
  `data.getArch()->types->getExactPiece(ct, node.getTypeOffset(), vn->getSize())`；
  :7666-7668 null 回退 `vn->getType()` 后 `newVn->updateType(newType)`。
- Rugra: 本地 `get_exact_piece` 副本（`Arc::new(ct.clone())` 丢 identity + 无 partial 构造）整体删除，
  全仓 grep 零残留；`type_factory` 循环外捕获一次（:12104，Ghidra 每 leaf 取同一 `getArch()->types`
  指针，语义等价）；leaf 处 `get_exact_piece(ct.clone(), type_offset as i64, vn_size)`——
  `ct.clone()` 是 Arc 浅拷贝，工厂返回 canonical Arc，identity 保留；
  `.or_else(|| vn.read().unwrap().get_type())` 同 cc:7666-7668；`any_addr_tied` or-累加同 cc:7643/7665。

### 1.5 本地副本删除与租约

- `exact_piece_arc_sub_type`（funcdata.rs）与 `RulePieceStructure::get_exact_piece`（ruleaction.rs）
  两个本地副本: grep src/+tests/ 零残留。
- Rust 侧 production `get_exact_piece` 调用点恰为四个: variable.rs:694、database.rs:324、
  funcdata.rs:271、ruleaction.rs:12154——与 commit 声明的"四调用点"精确吻合，无第五处遗漏。
- coreaction.rs 全 diff 仅两个 hunk，均位于 `ActionNameVars::link_symbols`（:4619-4624 捕获、
  :4708-4723 addr-tied 调用），紧邻 `impl Action for ActionNameVars` 边界之前——租约
  "仅 ActionNameVars 一处改动"满足。
- 门禁工具实测: `check_ghidra_annotations.py --all` 95 文件全过；
  `check_ghidra_refs.py --all --strict` OK。

## 2. 四类决定性语义核对表

| 调用点 | 引用/Arc identity | 循环边界/遍历 | 计数器/累加器 | 比较键 |
|---|---|---|---|---|
| variable.cc:551 ↔ variable.rs:670 | Ghidra `TypeFactory*` 指针（coreaction.cc:2946 一次捕获）；Rust `&mut` 同一 Architecture 工厂，`v_type.set(tp)` 保留 canonical Arc | 无循环；`inst[0]` ↔ `instances.first()` | `off<0→0`（cc:557-558）per-call 无共享 | 结果 null‖TYPE_UNKNOWN 早退（cc:561-562） |
| database.cc:151 ↔ database.rs:310 | Ghidra 经 scope→arch 到工厂拥有的指针；Rust 显式传同一工厂，返回工厂 canonical Arc | 无循环；isDynamic 二分（cc:156-159） | `off=(int4)(inaddr-addr)+offset` i32 截断对齐 | 无比较；委托 getExactPiece（offset/size 语义在工厂内，fixture 覆盖 beyond/wrong-size/cross-field/union/array） |
| funcdata_varnode.cc:938 ↔ funcdata.rs:2542 | ct 经同一工厂投影（cc:957 链）；flag/type 突变 per-varnode | loc 迭代（beginLoc/endLoc ↔ loc_tree 快照+index，排序键 space,offset,size,…） | `entry->getSize()>=vn->getSize()`（cc:955）；fl 重建与小符号清位（cc:967） | TYPE_UNKNOWN 丢弃（cc:958-959） |
| ruleaction.cc:7607 ↔ ruleaction.rs:12041 | 每 leaf 同一 `getArch()->types` ↔ 循环外一次捕获；`ct.clone()` 保 Arc identity | `for(i=0;i<stack.size();++i)`（cc:7645）↔ `0..stack.len()` 栈序 | `anyAddrTied` or-累加（cc:7643/7658/7665） | `vn->getAddr()==baseAddr+typeOffset`（cc:7650）；null 回退 vn->getType()（cc:7666-7668） |

getExactPiece 本体（type.cc:4090-4117 ↔ typefactory.rs:1684）：`getSize() < size+curOff` 越界 break
（int8 提升以 i128 保语义）、`getSize()==size` 完整命中返回自身、UNION→partialUnion、下钻
lastType/lastOff、尾部 STRUCT/ARRAY→partialStruct、unstripped ENUM→partialEnum、否则 null——逐条
一致（651045a 已落地部分，本 commit 未改，双侧 fixture 直接验证）。

## 3. fixture 证据与 pin 有效性

- metadata（tests/oracle/exactpiece_callers_1204.metadata.json）: 20 条 expected_lines，
  前缀计数 entry=8 / finalize=5 / sync=5 / rule=2，与 commit 声明一致。
- 边界语义覆盖实测: entry_beyond（off=22,sz=16 越界→null）、entry_wrong_size_partial
  （错尺寸→partial_struct:16@0）、entry_cross_partial（跨字段→partial_struct:4@2）、
  entry_union_partial（→partial_union:4@1）、entry_array_elem（数组元素）；finalize_null
  （off=9,sz=2→不 finalize）、finalize_unknown；sync_unknown_drop（cc:958-959）、
  sync_small_symbol（cc:967）；rule_leaf_identity / rule_low_partial。
- canonical identity 通道: 双侧同进程内指针/Arc 相等位（same_symbol/same_expected/repeat_same/
  direct_same），partial 用 `getTypePartialStruct(outer,2,4)` 直接构造对照 `Arc::ptr_eq`——
  真正验证"调用点与手工工厂调用返回同一 canonical 对象"，不是形状相似。
- Rust fixture 接线 `arch.types = Some(factory_arc)` + `fd.arch = Some(arch_arc)`，
  sync 记录经 `fd.get_arch()` 真实捕获链——被测路径就是 production 的 arch 捕获代码。
- pin 三件套实测: `git rev-parse 26116cc^{tree}` = `21cfe671…` 与 metadata 一致；
  8 个 critical blobs（variable/database/funcdata/ruleaction/coreaction.rs、Cargo.toml/lock、build.rs）
  的 git blob id 逐个与 `26116cc:<path>` 实测相等；57d4c0f 的 diff 恰为 10 行 PENDING→真实值。
- runner 构建模型: C++ 侧 `git archive e40ed130` 锁定 cpp 树重新编译；Rust 侧 `git archive 26116cc`
  冻结候选（Cargo 不读活源码）；`-i` 清洁环境 + flock；PENDING pin 正常模式拒绝（:162 reject_pending）。
  复核 Agent 实跑通过（§0）。

## 4. 行号引用修正

- `7625→7607`: grep 实测 `ruleaction.cc:7607 int4 RulePieceStructure::applyOp(PcodeOp *op,Funcdata &data)`
  为定义起始行；7625 是函数体内 `return 0;`。修正正确，且函数体区间 `7607-7700` 与实测
  （7700 为闭括号）一致（旧注释 7625-7718 两端皆错）。
- `7685→7665`: grep 实测 `ruleaction.cc:7665` 恰为 `data.getArch()->types->getExactPiece(ct, node.getTypeOffset(), vn->getSize())`。
  修正正确。
- 其余引用抽查: coreaction.cc:2946/2971-2972、database.cc:151/156-159/161、variable.cc:551/554/557-558/560-565、
  funcdata_varnode.cc:938/947-948/955/956-960/962-969/1093-1095 全部与实测行号吻合。
- `check_ghidra_refs.py --all --strict` 通过（全部 `// Ghidra:` 引用可解析）。

## 5. 残余声明核实（如实登记，未掩盖）

metadata.coverage 三条 UNTESTED 实测属实:

1. `symbol_entry_update_type: UNTESTED` — grep 全仓确认 `SymbolEntry::update_type`（工厂签名版）
   零 production caller（其余 `.update_type(` 命中均为 Varnode/HighVariable 不同函数）。
2. `dynamic_entry_offset_branch: UNTESTED` — fixture 无 hash-mapped SymbolEntry，database.cc:157
   分支未跑（Rugra `is_dynamic()` 分支代码在位）。
3. `arch_missing_fail_closed: UNTESTED` — 主管线 examples（curl/httpd worker_architecture）不设
   `arch.types`，四调用点 fail-closed 路径在主管线实际生效（跳过类型投影/回退旧类型），
   属 Rust 侧接线域外，不冒充 oracle-comparable。与 TYPE-WIRING-0001/ACTION-INFERTYPES 等
   已登记 TODO 一致。

这些 UNTESTED 均按机制 B2 如实降级，未将 fixture 未覆盖面谎报为 MATCH；overall_status 措辞
"MATCH (covered projection)" 明确限定覆盖域。

## 6. 建议（非阻断）

1. TODO_BOARD.md 无 `TYPEFACTORY-EXACTPIECE-CALLERS-0001` 行，且 :311
   `TYPEFACTORY-EXACTPIECE-0001` 仍写"当前仍零 production caller，下一步迁移四处本地 fallback"——
   该状态已被 26116cc 完成，行未同步（若按惯例由 root 集成时统一更新应在交接中注明；铁律 3
   期望同 commit 更新）。
2. variable.rs:678-682 两个 pre-existing 防御分支（`cur = get_type().unwrap_or_else(|| v_type.get())`、
   `sz = instances.first()…unwrap_or(cur.get_size())`）无 Ghidra 对应（Ghidra 直接
   `symbol->getType()` / `inst[0]`，空时为 UB 崩溃而非回退）。域内不可达（HighVariable 恒有实例、
   Symbol 恒有类型），且非本 commit 引入；建议后续以域内不变量注释钉死或对齐移除。
3. Ghidra 12.0.4 全局共 7 个 getExactPiece 消费点；本 commit 的四个是 Rugra 侧全部已有 fallback，
   其余（coreaction.cc:5024 `ActionInferTypes::buildLocaltypes`、coreaction.cc:5241、
   subflow.cc:2937、typeop.cc:220）在 Rugra 侧尚未移植——分别已有登记
   （ACTION-INFERTYPES-DISPATCH-0001 BLOCKED；typeop.rs:778 / subflow.rs:4645,4984 注释为已知限制）。
   commit 措辞未夸大，但账本跟进时应列出这批待迁移点，避免"canonical API 已被全部调用点消费"误读。
4. ruleaction apply_op 的 `needs_resolution/inheritResolution/resolveInFlow`（cc:7686-7694）未建模
   （pre-existing，代码注释在案）；待 TypePointerRel/needs_resolution 基础设施落地后补。
5. ActionNameVars 以注释 "The local map is never global" 代替 Ghidra
   `!sym->getScope()->isGlobal()` 显式检查（pre-existing）；建议在 ScopeLocal 持有 global 视图后补显式判断。

## 7. 判定

四调用点确已全部消费同一 Architecture-owned canonical `TypeFactory::get_exact_piece`；
两个丢 identity/丢 partial 的本地副本删除无残留；四类决定性语义逐条对齐；双侧 20 记录 fixture
经复核 Agent 独立实跑 MATCH byte-identical（sha `11dc00e9…` 双侧一致、stderr 双空）；
pin 三件套（commit/tree/8 blobs）实测有效；行号修正正确；残余以 UNTESTED 如实登记。
未发现 MISMATCH。

**APPROVE**
