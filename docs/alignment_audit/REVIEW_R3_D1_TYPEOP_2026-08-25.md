# R3 独立复核报告 — TYPEOP-LOCALTYPE-DISPATCH-0001 D1（机制 C）

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-typeop-localtype-d1`，分支 `agent/typeop-localtype-d1`，HEAD `9c79d96`（候选 `8b8b541` + `9c79d96`）
- 复核人：独立 Cross-Review Agent（未采信实现者 Evidence 声明，Ghidra 原文逐行自读）
- Oracle：`e40ed13014025f82488b1f8f7bca566894ac376b`（Ghidra_12.0.4_build，worktree ghidra symlink → 主仓，`git rev-parse HEAD` 已核实一致）
- 日期：2026-08-24
- 结论：**APPROVE**（附 7 条非阻断建议）

---

## 0. Ghidra 原文语义记录（本人自读，typeop.cc:687-718）

```cpp
Datatype *TypeOpCall::getInputLocal(const PcodeOp *op,int4 slot) const
{
  vn = op->getIn(0);
  if ((slot==0)||(vn->getSpace()->getType()!=IPTR_FSPEC))   // :695
    return TypeOp::getInputLocal(op,slot);                  // :696 → :271-275
  fc = FuncCallSpecs::getFspecFromConst(vn->getAddr());     // :699
  ProtoParameter *param = fc->getParam(slot - 1);           // :703
  if (param != (ProtoParameter*) 0) {                       // :704
    if (param->isTypeLocked()) {                            // :705
      ct = param->getType();
      if ((ct->getMetatype() != TYPE_VOID) && (ct->getSize() <= op->getIn(slot)->getSize()))
        return ct;                                          // :708
    }
    else if (param->isThisPointer()) {                      // :710 else-if！
      ct = param->getType();
      if (ct->getMetatype() == TYPE_PTR && ((TypePointer*) ct)->getPtrTo()->getMetatype() == TYPE_STRUCT)
        return ct;                                          // :714（无 size 检查）
    }
  }
  return TypeOp::getInputLocal(op,slot);                    // :717
}
```

支撑语义（均自读核实）：
- 基类 `TypeOp::getInputLocal`（typeop.cc:271-275）= `tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN)`；`tlst` 是 TypeOp 构造时（typeop.cc:233）由 Architecture 传入的 TypeFactory。
- `FuncCallSpecs::getFspecFromConst`（fspec.hh:1733）= `(FuncCallSpecs*)(uintp)addr.getOffset()` —— 地址即指针，同一 Funcdata 拥有的分配。
- `FunctionPrototype::getParam`（fspec.hh:1532）→ `store->getInput(i)`；`ProtoStoreInternal::getInput`（fspec.cc:3372-3377）越界返回 NULL；`ProtoStoreSymbol::getInput`（fspec.cc:3245-3253）越界亦 NULL。
- `newVarnodeCallSpecs`（funcdata_varnode.cc:205-213）：fspec 空间、offset=原始指针、size=`sizeof(fc)`、类型 `getBase(sizeof,UNKNOWN)`、`assignHigh`，**不设 annotation flag**，fspec 空间唯一铸造点。
- `PcodeOp::inputTypeLocal`（op.hh:252）= `opcode->getInputLocal(this,slot)` —— C++ fixture 经真实 Architecture-owned 虚派发。

## 1. 四类决定性语义核对表

### 1.1 引用/输出参数 — **PASS**

| 语义点 | Ghidra（行号） | Rugra（worktree 行号） | 判定 |
|---|---|---|---|
| op 引用 | `const PcodeOp*` 只读（typeop.cc:687） | `&PcodeOp` 只读（typeop.rs:1292） | ✓ |
| 返回值 | 原始 `Datatype*`，指向 TypeFactory canonical 对象，**无拷贝**（:706/:708、:712/:714、基类 :274） | `Option<Arc<Datatype>>`，`Some(ct.clone())` 仅 Arc 引用计数（typeop.rs:1329/1339）；fixture `expected_identity/param_identity/fallback_identity/repeat_identity` 全部 `Arc::ptr_eq`（fixture:102-110），与 oracle 指针等值位逐字节一致 | ✓ |
| callspec 获取 | `getFspecFromConst(vn->getAddr())` 地址→指针（:699, fspec.hh:1733） | `input0.get_call_spec()` = `Weak::upgrade`（varnode.rs:216-219），同一 Funcdata 稳定 Arc 分配；Weak 失效→fallback（保守超集，Ghidra 悬垂 fspec 为不可达/UB） | ✓（表示残差见 §2） |
| 工厂持有 | TypeOp 基类 `tlst`（构造注入，typeop.cc:233/660） | `TypeOpCall { type_factory }` 构造注入（typeop.rs:1253-1260），trait object 无状态故上移到具体类，已注释 | ✓ |

### 1.2 循环边界/遍历顺序 — **PASS**

- Ghidra 无循环；守卫顺序固定：`(slot==0)||(space!=IPTR_FSPEC)`（:695）→ `getParam(slot-1)`（:703）→ `isTypeLocked` 分支**优先于** `else if isThisPointer`（:705/:710）→ 终局基类（:717）。
- Rust 同序（typeop.rs:1300-1360）：`slot==0` → Iop+ANNOTATION 门 → `prototype.get_param(slot-1)`（slot≥1 无下溢；`Vec::get`→`Option` = Ghidra 越界 NULL，fspec.rs:333-335 ↔ fspec.cc:3372-3377）→ `is_type_locked`（Void 拒绝+size≤）`else if is_type_pointer`（Pointer 变体+ptr_to Struct）→ `.or_else(fallback)`。
- 关键细节核实：type-locked 但 VOID/oversize 拒绝后**不落入** this-pointer 分支（Ghidra `else if` 挂在 isTypeLocked 上，Rust 同构 `if/else if`，闭包返回 None 后 `or_else(fallback)`）✓。双侧 13 例含 `locked_void`/`locked_oversize`/`unlocked_this_plain` 负例逐字节一致。

### 1.3 计数器/累加器 — **PASS**

- Ghidra 唯一索引换算 `slot-1` 恰一次（:703），无累加器。
- Rust `get_param(slot - 1)` 一次（typeop.rs:1321），无计数器。
- 活状态读取（非 snapshot 旁路）证明：`locked_ptr_after_unlock`（清锁→fallback）与 `locked_ptr_after_relock`（复锁→char*）两例每次调用都读 live callspec，双侧字节一致 → 无缓存/snapshot。

### 1.4 排序/比较键 — **PASS**

| 比较键 | Ghidra | Rugra | 判定 |
|---|---|---|---|
| 空间判定 | `space->getType()!=IPTR_FSPEC`（:695） | `space==Iop && is_annotation` + Weak（typeop.rs:1305-1310） | ✓（等价性见 §2） |
| type-lock 优先序 | `isTypeLocked` → `else if isThisPointer`（:705/:710） | `is_type_locked` → `else if is_this_pointer`（fspec.rs:212-216/188-192 ↔ fspec.hh:1108/1111） | ✓ |
| metatype≠VOID | `ct->getMetatype()!=TYPE_VOID`（:707） | `ct.get_metatype()!=TypeMetatype::Void`（typeop.rs:1327） | ✓ |
| size 逐操作符 | `ct->getSize() <= op->getIn(slot)->getSize()`（:707，`<=` 含等号） | `ct.get_size() <= input_size`（typeop.rs:1328，`input_size` 取自 `op.get_in(slot)`，入口一次） | ✓（`locked_small_fits` 4≤8 与 `locked_oversize` 16>8 双向验证） |
| this-pointer | `TYPE_PTR && ptrTo==TYPE_STRUCT`，**无 size 检查**（:713） | `Datatype::Pointer` 变体匹配（≡metatype PTR）+ `ptr_to.get_metatype()==Struct`（typeop.rs:1333-1338），无 size 检查；`ptr_to: Arc<Datatype>`（datatype.rs:2513）= `getPtrTo()` 点位对象 | ✓ |

## 2. fspec 空间门等价性（Iop+ANNOTATION+Weak 三元组） — **PASS（登记残差）**

- Ghidra 识别集 = fspec 空间全体 = `newVarnodeCallSpecs` 铸造集（fspec 空间唯一使用点，funcdata_varnode.cc:205）。
- Rust 识别集 = `bind_call_spec` 铸造集（全仓唯一调用点 funcdata.rs:8295，位于 `new_varnode_call_specs` 内，铸造时同时置 Iop 空间+ANNOTATION+Weak，funcdata.rs:8276-8301）。
- 两门各自与自己的铸造集同延 → 可达状态上语义等价。`is_annotation` 是 Rust 侧加强条件（Ghidra fspec varnode 不设 annotation flag），由于铸造时必然置位，不改变识别集。
- 负例控制：`constant_same_offset`（Const 空间、同数字 offset 的仿冒 varnode）双侧都落 fallback → 数字位不参与身份，禁止地址扫描得到实证。
- 表示残差如实暴露而非掩盖：双侧打印 `representation.fspec_name`（fspec vs iop）与 `representation.fspec_type`（4 vs 5；本人核对 space.hh `IPTR_FSPEC=4`/`IPTR_IOP=5` 与 Rugra `SpaceType`（space.rs:888-906）`Fspec=4`/`Iop=5`，两侧枚举值本身各自与 Ghidra 对齐），绑定已登记 `TYPEOP-FSPEC-SPACE-0001`（TODO_BOARD.md:309，P0 MISMATCH）与 `CALLSPEC-0001`（metadata residuals）。

## 3. canonical fallback 同源 — **PASS**

- fallback 闭包走 `self.type_factory.read().get_base(input_size, Unknown)`（typeop.rs:1297-1301）；`TypeFactory::get_base` 经 base_cache/base_type_tree 实习返回 canonical Arc（typefactory.rs:422-465）。
- 同一分配证明：fixture 用 `architecture.set_types(type_factory.clone())` + `vbank.set_type_factory(type_factory.clone())` + `TypeOpCall::new(architecture.types…clone())`（arch.rs:2290 / varnode.rs:2221），三个消费者共享同一 Arc；`fallback_identity=1`（Arc::ptr_eq）与 oracle `actual==factory->getBase(...)` 指针等值逐字节一致。
- bootstrap 镜像核实：`configure_factory()` 的 `<size_alignment_map>`（1,2,4,8,16）与 `sleigh_specs/x86-64-gcc.cspec` 逐项相同；core types 23 项与 `SleighArchitecture::buildCoreTypes` else 分支（sleigh_arch.cc:204-238）**顺序与内容逐项相同**。无地址扫描、无字符串硬编码、无 snapshot 旁路。

## 4. 三处 WIP 缺陷修复核验

1. **fspec 门缺失 → 已修且必要**：终态代码含完整三元组门（typeop.rs:1304-1318）；`constant_same_offset` 负例证明缺门则会错误解码数字位。
2. **bootstrap 除零 → 修复正确；WIP 崩溃本身不可复现**：旧 fixture 用 `TypeFactory::new(8)`（DataOrg flavor、raw 阶段空 align_map；typefactory.rs:687-700 显示空 map 下强制路径 Err/遗留路径 primitive_layout），新 `configure_factory()` 镜像 oracle 真实 bootstrap（见 §3）。修复的必要性方向成立（对齐 bootstrap 消除空 map 布局路径）；具体"除零"症状因 WIP 未入历史无法独立复验——非阻断。
3. **printRaw 投影 → 已修且必要**：`ghidra_print_raw`（fixture:152-162）忠实实现 `Datatype::printRaw`（type.cc:139-146：name 否则 `unkbyte<size>`）与 `TypePointer::printRaw`（type.cc:910-917：`ptrto->printRaw + " *"`，spaceid 非空才加后缀；工厂 `getTypePointer` 产物 spaceid=null）。投影从**实际返回的 Datatype**（name/size/pointer 性质）派生，非手写 expected；`ghidra_metatype` 18 个枚举映射逐值对照 type.hh:79-98 全部正确（Rust 内部 TypeMetatype 判别值与 Ghidra 不同，故需该全函数投影）。必要性成立：Rugra 自带 `Datatype::print_raw` 的 struct/array 拼写与 oracle 发散，直接调用会产生与本函数无关的伪差异。

## 5. 双侧证据链核验（167 records / 2 行差异） — **与证据一致**

- **记录数独立推算**（不依赖跑 runner）：头 11 行（fixture/architecture/fspec_name/fspec_type/constant_type/5 个 roundtrip-alias 行）+ 13 例 × 12 行（slot,input_size,param_present,param_locked,param_this,result_type,result_meta,result_size,4 个 identity）= **167**，与双侧记录数吻合。
- **字节差独立推算**：6369−6367=2 = len("fspec")−len("iop")=5−3；`fspec_type` 4 vs 5 等宽。✓
- **diff 12 records** = 2 文件头（---/+++）+1 `@@`+2 前导 ctx+2`-`+2`+`+3 后随 ctx，两差异行相邻成单 hunk。✓
- metadata `paired_expected.bilateral.differing_lines` 明确列出的就是那 2 行表示差异；overall 如实记 **MISMATCH**、不宣称 L3。
- runner（tools/run_typeop_local_type_oracle.sh）为硬锁定 harness：oracle 按 commit/tag/cpp-tree/Makefile-blob+脏树检查锁定；Rust 侧从 `git archive 8b8b541` 冻结快照构建（overlay 表为空）；双侧各跑 2 次查确定性；sha256 全量 pin 且 run 前后两次 `verify_owned_inputs`；`8b8b541..HEAD` 的 `src/` 零改动（diff 为空已核实），即被测生产代码 = 候选提交代码。C++ fixture 经真实 `BfdArchitecture`+`PcodeOp::inputTypeLocal` 虚派发（非链接期替换）。
- 覆盖 13 例含全部关键边界：slot0、locked 精确/偏小、unlocked、VOID、oversize、this→struct、this→非 struct、缺参越界、解锁/复锁（活状态）、别名 fspec、Const 同 offset 仿冒。

## 6. 结论

**APPROVE**。`TypeOpCall::get_input_local`（typeop.rs:1291-1360）与锁定 oracle `TypeOpCall::getInputLocal`（typeop.cc:687-718）在四类决定性语义上逐条等价；fspec 空间门在可达状态上等价且残差已登记绑定 `TYPEOP-FSPEC-SPACE-0001`/`CALLSPEC-0001`；双侧 fixture 证据链自洽且可独立推算验证；整体诚实保持 MISMATCH（不升 L3）。D2（ActionInferTypes caller 闭包）按 metadata `untested` 清单另行 fixture 的处理正确。

## 7. 建议（非阻断）

1. **TODO_BOARD.md:308 未随候选提交更新 D1 evidence**：该行仍停在 D0 状态+D1 要求（2026-08-24），未登记 `8b8b541`/`9c79d96` 为 D1 证据 commit。按铁律 3（验证完成/送审当轮更新 TODO），集成时必须补上。
2. **trait 默认值发散（预存）**：`TypeOp::get_input_local` trait 默认返回 `None`（typeop.rs:126），Ghidra 基类默认是 `tlst->getBase(...)`。TypeOpCall 已正确内联基类行为，但后续 D1 系列移植其他 opcode 的 get*Local 时应把 canonical base 查找抽成共享 helper，避免每个 impl 复制 fallback 闭包导致漂移。
3. **`TypeOpCall::get_flags` 返回 0**（typeop.rs:1272）vs typeop.cc:663 `opflags = special|call|has_callspec|coderef|nocollapse`——预存缺口，非本次 write-set，建议入账。
4. "bootstrap 除零"WIP 症状不可从历史复现（WIP 未提交）；后续类似声明建议保留可复现的最小现场或在 commit message 中记录现象。
5. Rugra `Datatype::print_raw` 的 struct/array 拼写发散（fixture 投影绕开的对象）未见独立 TODO 登记，建议入账以免被 fixture 投影长期掩盖。
6. runner 结束即删 `run_root`，双侧 stdout 仅以 sha256 形式存于 metadata；建议归档一份双侧产物对（如 `tests/oracle/archives/`）便于审计直接查看 167 行原文。
7. Rust 对越界 slot 返回 `None`（`op.get_in(slot)?`）而 Ghidra 越界为越约抛错——契约内调用方不可达的防御性超集，无害，记录在案。
