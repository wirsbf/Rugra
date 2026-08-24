# B1 — PTRSUB 字段类型传播（propagateAddIn2Out → downChain）逐行移植方案

只读审计报告，2026-08-24。Oracle：Ghidra 12.0.4 tag `Ghidra_12.0.4_build`，commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。仓库 `/home/wirs/DEV/Rugra`（只读，未改动任何文件、未运行 cargo）。

**分叉根因（一句话）**：Rust 生产类型传播 dispatch（`src/coreaction.rs:3970-3991`）把
PTRSUB/INT_ADD/PTRADD（甚至 INT_SUB）的输入指针**原样**传给输出（`Some(alttype.clone())`），
而 Ghidra 走 `TypeOpPtrsub::propagateType` → `TypeOpIntAdd::propagateAddIn2Out` →
`TypePointer::downChain`（+`getTypePointerRel`）把 `ProgressData *` 逐层消耗 offset 变换成
字段 pointer / 容器相对 PointerRel；Rugra 已 1:1 移植的 `down_chain`/`down_chain_pointer`/
`propagate_add_pointer` **没有任何 production caller**，offset 从不被消耗，导致
progressbarinit 的 `->total` 链每轮 InferTypes（上限 7 pass）继续增厚。

---

## 1. Ghidra 三个函数逐字摘录 + 四类决定性语义核对

### 1.1 `TypeOpPtrsub::propagateType`（typeop.cc:2366-2378）

```cpp
Datatype *TypeOpPtrsub::propagateType(Datatype *alttype,PcodeOp *op,Varnode *invn,Varnode *outvn,
				      int4 inslot,int4 outslot)
{
  if ((inslot!=-1)&&(outslot!=-1)) return (Datatype *)0; // Must propagate input <-> output
  type_metatype metain= alttype->getMetatype();
  if (metain != TYPE_PTR) return (Datatype *)0;
  Datatype *newtype;
  if (inslot == -1)		// Propagating output to input
    newtype = (Datatype *)0;	// Don't propagate pointer types this direction
  else
    newtype = TypeOpIntAdd::propagateAddIn2Out(alttype,tlst,op,inslot);
  return newtype;
}
```

四类决定性语义：
- **引用/输出参数**：`alttype` 只读入参；`tlst` 是 TypeOp 成员的 `TypeFactory*`，
  **以引用穿透给 propagateAddIn2Out 并在其中被改写**（intern 新 pointer/rel-pointer 类型）。
  返回 `Datatype*`，NULL = 阻断传播。`invn/outvn` 在本函数未用（仅基类接口形状）。
- **循环边界/遍历顺序**：无循环。守卫顺序固定：① `inslot!=-1 && outslot!=-1` → 0；
  ② `metatype != TYPE_PTR` → 0；③ `inslot == -1`（output→input）→ 0；
  ④ 其余（inslot>=0 且 outslot==-1）→ 委托 `propagateAddIn2Out`。**只做 input→output**。
- **计数器/累加器**：无。
- **排序/比较键**：仅 metatype 等值（`TYPE_PTR`），不看 submeta/size；接受与否由调用方
  `ActionInferTypes::propagateTypeEdge` 的 `typeOrder` 比较（coreaction.cc:5104，
  `0 > newtype->typeOrder(*outvn->getTempType())` 才写入）决定。

### 1.2 `TypeOpIntAdd::propagateAddIn2Out`（typeop.cc:1215-1253）

```cpp
Datatype *TypeOpIntAdd::propagateAddIn2Out(Datatype *alttype,TypeFactory *typegrp,PcodeOp *op,int4 inslot)
{
  TypePointer *pointer = (TypePointer *)alttype;
  uintb offset;
  int4 command = propagateAddPointer(offset,op,inslot,pointer->getPtrTo()->getAlignSize());
  if (command == 2) return (Datatype *)0; // Doesn't look like a good pointer add
  TypePointer *parent = (TypePointer *)0;
  int8 parentOff;
  if (command != 3) {
    int8 typeOffset = AddrSpace::addressToByteInt(offset,pointer->getWordSize());
    bool allowWrap = (op->code() != CPUI_PTRSUB);
    do {
      pointer = pointer->downChain(typeOffset,parent,parentOff,allowWrap,*typegrp);
      if (pointer == (TypePointer *)0)
	break;
    } while(typeOffset != 0);
  }
  if (parent != (TypePointer *)0) {
    // If the innermost containing object is a TYPE_STRUCT or TYPE_ARRAY
    // preserve info about this container
    Datatype *pt;
    if (pointer == (TypePointer *)0)
      pt = typegrp->getBase(1,TYPE_UNKNOWN); // Offset does not point at a proper sub-type
    else
      pt = pointer->getPtrTo();	// The sub-type being directly pointed at
    pointer = typegrp->getTypePointerRel(parent, pt, parentOff);
  }
  if (pointer == (TypePointer *)0) {
    if (command == 0)
      return alttype;
    return (Datatype *)0;
  }
  if (op->getIn(inslot)->isSpacebase()) {
    if (pointer->getPtrTo()->getMetatype() == TYPE_SPACEBASE)
      pointer = typegrp->getTypePointer(pointer->getSize(),typegrp->getBase(1,TYPE_UNKNOWN),pointer->getWordSize());
  }
  return pointer;
}
```

它消费的底层分类器 `TypeOpIntAdd::propagateAddPointer`（typeop.cc:1268-1316，Rust 已移植）：
- PTRADD：slot!=0 → 2；const 索引 → `off = const*mult & calc_mask`，off==0 → 0 否则 1；
  非 const 且 `mult % sz != 0` → 2；否则 3（原样穿透）。
- PTRSUB：slot!=0 → 2；`off = in(1)->getOffset()`，off==0 → 0 否则 1。
- INT_ADD：另一操作数非 const 时看 INT_MULT(`mult % sz`/-1)→ 3/2，`sz==1` → 3 否则 2；
  const 且被标为 TYPE_PTR → 2；const → off==0 ? 0 : 1。其他 op → 2。

四类决定性语义：
- **引用/输出参数**：`typegrp` 指针——factory 被真实改写（downChain 内 getBase/
  getTypePointer/getTypePointerStripArray，此处 getBase/getTypePointerRel/getTypePointer
  全部 intern）。`offset`（uintb）是 `propagateAddPointer` 的 **out 参数**；
  `typeOffset`（int8）是 downChain 的 **in/out** 参数（被 `getSubType` 就地重规范化）；
  `parent`/`parentOff` 是跨整个 do-while 循环共享的 out 累积槽——**循环前清一次
  （NULL/未初始化），downChain 只在当前 ptrto 是 struct/array 时写入，从不重置**。
  `pointer` 是循环迭代替换变量，初值 = alttype。
- **循环边界/遍历顺序**：`do { pointer = downChain(...) } while (pointer != NULL &&
  typeOffset != 0)`——**do-while，至少执行一次**（仅当 command != 3；command==3
  穿透时完全跳过，pointer 保持 alttype）。每次 downChain 只下降一层；终止条件是
  downChain 返回 NULL 或重规范化 offset 归零。**无显式深度上限**（终止性依赖 offset
  消耗/NULL）。`allowWrap = op->code() != CPUI_PTRSUB`：PTRSUB 永不回绕。
  `typeOffset = AddrSpace::addressToByteInt(offset, pointer->getWordSize())`
  （space.hh:532，即 `off * ws`，uintb→int8 隐式转换）。
- **计数器/累加器**：无计数器；`parentOff` 是 per-call 累积器（最后一次 struct/array
  容器写入生效）。注意 `getTypePointerRel(parent, pt, parentOff)` 用的是**循环结束时**
  的 parent/parentOff 快照。
- **排序/比较键**：本函数无比较；决定性的是 **重载选择**：1241 调
  `getTypePointerRel(TypePointer*, Datatype*, int4)`（type.cc:4016-4025，ephemeral 无名
  重载，`markEphemeral` 后 findAdd intern）——不是 type.cc:4029 的具名重载。
  其余决定性分支：downChain 全灭但 parent 存在 → `pt = getBase(1,TYPE_UNKNOWN)`
  （指进容器但不在字段起点）；pointer==NULL 时 `command==0`（加 0）退回 alttype、
  否则 NULL；spacebase 输入且 ptrto 为 TYPE_SPACEBASE → 改写为 unknown 基类型指针
  （size/wordsize 取自**结果** pointer，非输入）。

### 1.3 `TypePointer::downChain`（type.cc:1084-1121）

```cpp
TypePointer *TypePointer::downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,TypeFactory &typegrp)
{
  int4 ptrtoSize = ptrto->getAlignSize();
  if (off < 0 || off >= ptrtoSize) {	// Check if we are wrapping
    if (ptrtoSize != 0 && !ptrto->isVariableLength()) {	// Check if pointed-to is wrappable
      if (!allowArrayWrap)
        return (TypePointer *)0;
      intb signOff = sign_extend(off,size*8-1);
      signOff = signOff % ptrtoSize;
      if (signOff < 0)
        signOff = signOff + ptrtoSize;
      off = signOff;
      if (off == 0)		// If we've wrapped and are now at zero
        return this;		// consider this going down one level
    }
  }

  if (ptrto->isEnumType()) {
    // Go "into" the enumeration
    Datatype *tmp = typegrp.getBase(1, TYPE_UINT);
    off = 0;
    return typegrp.getTypePointer(size,tmp,wordsize);
  }
  type_metatype meta = ptrto->getMetatype();
  bool isArray = (meta == TYPE_ARRAY);
  if (isArray || meta == TYPE_STRUCT) {
    par = this;
    parOff = off;
  }

  Datatype *pt = ptrto->getSubType(off,&off);
  if (pt == (Datatype *)0)
    return (TypePointer *)0;
  if (!isArray)
    return typegrp.getTypePointerStripArray(size, pt, wordsize);
  return typegrp.getTypePointer(size,pt,wordsize);
}
```

四类决定性语义：
- **引用/输出参数**：`off` int8& in/out（先可能被 wrap 改写，再被 `getSubType` 第二参数
  就地重规范化为组件内偏移）；`par` TypePointer*& out（= `this`，**容器指针本身**，
  仅当 ptrto 为 struct/array 写入）；`parOff` int8& out（写入的是 **getSubType
  重规范化之前**的 off）；`typegrp` TypeFactory& 引用改写。返回新 pointer 或 NULL。
  **每次调用只下降一层**（doc："only goes down one level at most"）。
- **循环边界/遍历顺序**：无循环；守卫顺序决定性：① `off < 0 || off >= ptrtoSize`
  （**ptrtoSize = `getAlignSize()`**，非 getSize）；② `ptrtoSize != 0 &&
  !ptrto->isVariableLength()`；③ `!allowArrayWrap → NULL`；④ `sign_extend(off,
  size*8-1)`——**size 是指针自身宽度**；⑤ `% ptrtoSize` + 负数补偿；⑥ 归零 →
  `return this`（算下降一层）。enum 分支在 wrap 之后、struct/array 之前；
  `par/parOff` 写入在 `getSubType` 之前。
- **计数器/累加器**：无。
- **排序/比较键**：`getSubType(off,&off)` 的字段定位键 = 偏移落点（struct 二分/线性
  找到的 component 起点，返回剩余偏移）；末尾分派键 `isArray`：array →
  `getTypePointer`（保留元素类型原样），非 array → `getTypePointerStripArray`
  （剥掉 pt 上的 array 层）。

**虚分派注意**：`pointer->downChain(...)` 是虚调用；当输入 alttype 本身是
`TypePointerRel`（上一轮传播产物）时分派到 `TypePointerRel::downChain`
（type.cc:2656-2672）：off 落在 ptrto（`getSize()`，注意与 plain 版的 `getAlignSize()`
不同）内且 ptrto 为 struct/array → 退化 plain 版；否则 `relOff = (off + offset) &
calc_mask(size)` 越出 parent → NULL；`relOff==0 && offset!=0` → 直接返回 parent 指针
（不钻 0 偏字段）；否则以 parent 指针递归 plain downChain。Rust 对应物
`TypeFactory::down_chain`（typefactory.rs:1888-1936）已含全部语义，只是 parent/offset
由参数显式传入而非读 `pointer_rel` 状态。

---

## 2. Rust 现状 vs Ghidra 逐点差异表

（注：任务描述写 `src/types.rs`；实际类型系统位于 `src/type_system/`，down_chain 在
`src/type_system/typefactory.rs`。）

| # | 差异点 | Ghidra (file:line) | Rust (file:line) | 性质 |
|---|---|---|---|---|
| 1 | **生产 dispatch 指针原样穿透**：PTRSUB/INT_ADD/PTRADD/INT_SUB 四 opcode 合并一个 arm，pointer meta → `Some(alttype.clone())` 直接给 output，还给"非 const 兄弟 input" | typeop.cc:2366-2378（PTRSUB）、2268-2281（PTRADD）、1181-1201（INT_ADD）均经 propagateAddIn2Out 变换 | coreaction.rs:3970-3991 | **根因**。`ProgressData *` 整个穿透，offset 永不消耗 |
| 2 | INT_SUB 根本不该传指针：`TypeOpIntSub` 无 propagateType 覆写，基类 `TypeOp::propagateType` 返回 NULL | typeop.cc:317-321（基类）；typeop.cc def 列表无 IntSub | coreaction.rs:3970 把 `CPUI_INT_SUB` 放进指针 arm | 额外缺陷（同 arm 顺带修） |
| 3 | 指针向兄弟 input 传播：Ghidra 对这些 op 的指针路径只有 inslot>=0 且 outslot==-1（slot!=0 一律 command 2 → NULL），无 sibling-input 正向传播 | typeop.cc:2369/2271-2272/1191-1192 | coreaction.rs:3978-3986 显式向非 const 兄弟 input 传 | 需删除 |
| 4 | `propagateAddIn2Out` 不存在（分类器已移植但无消费者） | typeop.cc:1215-1253 | typeop.rs:2397-2510 仅 `propagate_add_pointer`（返回 `(command, off)` 元组替代 out 参数）；doc 自述"full down-chain reconstruction … is tracked separately" | 缺整函数 |
| 5 | `downChain` 已移植但 **零 production caller**；plain 版 `down_chain_pointer` 是私有 `fn`；rel 版 parent/offset 需调用方从 `pointer_rel` 状态提取，无虚分派 dispatcher | type.cc:1084-1121 / 2656-2672（虚分派） | typefactory.rs:1947-2014（plain，私有）、1888-1936（rel，pub）；仅测试 caller typefactory.rs:5960-5993 | 已有地基，缺接线 |
| 6 | `getTypePointerRel(TypePointer*,Datatype*,int4)` ephemeral 重载已有（对应 1241 调用点） | type.cc:4016-4025 | typefactory.rs:1800-1817 `get_type_pointer_rel_ephemeral` | 已具备 |
| 7 | trait 路径 `TypeOpIntAdd::propagate_type` 同样原样返回 `Some(alt_type.clone())`，doc 声称 faithful 但缺 propagateAddIn2Out 分支 | typeop.cc:1181-1201 | typeop.rs:2338-2362 | 双 dispatch 不一致（该路径当前非生产 caller） |
| 8 | `TypeOpPtrsub` 无 `propagate_type` 覆写，也无 `get_output_token` 覆写（后者 Ghidra 也用 downChain，print 期字段 token） | typeop.cc:2349-2364（getOutputToken）、2366-2378 | typeop.rs:1399-1459（仅 printRaw/push/getOutputLocal，getOutputLocal 还是"same type as input"的简化） | B1 邻接缺口，共享同一 down_chain plumbing |
| 9 | 生产 dispatch 是静态 match，无 TypeFactory 入参（`&IntTypes`+ptr_size）；无法 intern 新类型 | coreaction.cc:5100 `op->getOpcode()->propagateType(alttype,op,invn,outvn,inslot,outslot)`（tlst 经 TypeOp 成员可达） | coreaction.rs:3925-3932 签名；3847-3919 edge；4088 propagate_one_type；4343 apply | plumbing 缺口 |
| 10 | edge 前置 `alttype->needsResolution()` → `resolveInFlow(op,inslot)`；`outvn->stopsUpPropagation()` 阻断 | coreaction.cc:5081-5084、5093 | coreaction.rs:3847-3919 两者皆无（STOP 消费属 B1 后继 STOP 任务；resolveInFlow 属 ACTION-INFERTYPES-DISPATCH-0001） | 已登记缺口，与本片交互（PointerRel 输入是 needsResolution） |

已对齐确认（无需改）：`propagate_add_pointer` 分类器四 arm（typeop.rs:2397-2510 ↔
typeop.cc:1268-1316）；`down_chain_pointer` 的 wrap/enum/struct/array 语义与
`getAlignSize`/`parOff 写入时机`（typefactory.rs:1947-2014 ↔ type.cc:1084-1121）；
rel 版 `getSize()`（typefactory.rs:1899 ↔ type.cc:2660）与 plain 版 `getAlignSize()`
的刻意区分；`AddrSpace::address_to_byte_int`（space.rs:2015 ↔ space.hh:532）；7-pass
cap（coreaction.rs:4352-4357 ↔ coreaction.cc:5374-5416 内 local_count>=7）。

---

## 3. 精确移植方案

### 3.1 新增 `propagate_add_in2out`（src/typeop.rs，Ghidra: typeop.cc:1215）

```rust
// Ghidra: typeop.cc:1215 TypeOpIntAdd::propagateAddIn2Out
pub fn propagate_add_in2out(
    alttype: &Arc<Datatype>,
    typegrp: &mut TypeFactory,
    op: &PcodeOp,
    inslot: i32,
) -> Option<Arc<Datatype>> {
    let ptr0 = match alttype.as_ref() { Datatype::Pointer(p) => p.clone(), _ => return None };
    // sz = ptr_to.get_align_size()（Ghidra:1220 getPtrTo()->getAlignSize()）
    let (command, off) = TypeOpIntAdd::propagate_add_pointer(op, inslot, ptr0.ptr_to.get_align_size() as i32);
    if command == PropagateAddCommand::NoPropagate { return None; }        // 1221
    let mut parent: Option<Arc<Datatype>> = None;                          // 1222
    let mut parent_off: i64 = 0;
    let mut pointer = Some(alttype.clone());
    if command != PropagateAddCommand::Passthrough {                        // 1224-1232
        let mut type_offset = AddrSpace::address_to_byte_int(off as i64, ptr0.wordsize as u32);
        let allow_wrap = op.get_opcode() != OpCode::CPUI_PTRSUB;
        loop {                                                              // do-while
            let cur = pointer.clone()?;                                     // pointer==NULL -> break
            pointer = typegrp.down_chain_virtual(&cur, &mut type_offset, &mut parent, &mut parent_off, allow_wrap);
            if pointer.is_none() || type_offset == 0 { break; }
        }
    }
    if let Some(par_arc) = parent.clone() {                                 // 1233-1242
        let pt = match &pointer {
            None => typegrp.get_base(1, TypeMetatype::Unknown),             // 1238
            Some(p) => /* match Datatype::Pointer(p) => p.ptr_to.clone() */,
        };
        pointer = Some(typegrp.get_type_pointer_rel_ephemeral(par_arc, pt, parent_off)); // type.cc:4016 重载
    }
    let pointer = pointer?;                                                 // 1243-1247
    if /* op.get_in(inslot) is_spacebase */ {                               // 1248-1251
        if /* pointer.ptr_to metatype == Spacebase */ {
            return Some(typegrp.get_type_pointer(size, typegrp.get_base(1, Unknown), wordsize));
        }
    }
    Some(pointer)
}
```

要点（每条都对应决定性语义）：
- `command==Passthrough` 时**不进循环**，pointer 保持 alttype（Ghidra 1224 `if (command != 3)`）。
- do-while 语义：至少一次 downChain；`type_offset` 是被 `get_sub_type` 就地重规范化的
  in/out；`parent/parent_off` 跨迭代共享、只写不清。
- `getTypePointerRel` 必须**ephemeral 重载**（`get_type_pointer_rel_ephemeral`，
  typefactory.rs:1800），不得用 legacy 具名版 `get_type_pointer_rel`（typefactory.rs:1769，
  会制造 `Parent+off *` 具名类型，Ghidra 无此行为）。
- `off as i64`：Ghidra uintb→int8 隐式转换；负编码偏移（如 0xfffffffffffffffc）经
  `address_to_byte_int` 后为负，进入 downChain wrap 分支（PTRSUB → None）。
- spacebase 改写取**结果 pointer** 的 size/wordsize（Ghidra 1250 `pointer->getSize()/
  getWordSize()`），非输入指针的。

### 3.2 TypeFactory 虚分派 dispatcher（src/type_system/typefactory.rs，Ghidra: type.hh 虚 downChain）

在 `down_chain`/`down_chain_pointer` 旁新增一个 pub 入口，替代 C++ 虚分派：

```rust
// Ghidra: type.hh:488/665 downChain (virtual dispatch TypePointerRel vs TypePointer)
pub fn down_chain_virtual(&mut self, ptr: &Arc<Datatype>, off: &mut i64,
    par: &mut Option<Arc<Datatype>>, par_off: &mut i64, allow_array_wrap: bool) -> Option<Arc<Datatype>>
{
    match ptr.as_ref() {
        Datatype::Pointer(p) => match &p.base.pointer_rel {
            Some(state) => self.down_chain(p, &state.parent, state.offset, off, par, par_off, allow_array_wrap),
            None => self.down_chain_pointer(p, off, par, par_off, allow_array_wrap),
        },
        _ => None,
    }
}
```

（`down_chain_pointer` 保持私有即可；`PointerRelState`（datatype.rs:335-339）已带
`parent/offset/stripped`，正是 rel 版所需 side-table。）注意 rel 版
`down_chain`（typefactory.rs:1935）有 `result.or(Some(orig_pointer))` 尾式 fallback，
与 Ghidra type.cc:2671 `return origPointer->downChain(...)` 直接返回（可为 NULL）
**不同**——审计判定这是已有偏差，移植时一并按 oracle 修正为直接返回 downChain 结果，
或在报告中登记 MISMATCH。**这一处需要复核**（见 §3.6）。

### 3.3 生产 dispatch 改写（src/coreaction.rs，Ghidra: typeop.cc:2366/2268/1181/317）

把 coreaction.rs:3970-3991 的四合一 arm 拆成四个，逐字按 Ghidra 守卫顺序：

- `CPUI_PTRSUB`：① `inslot!=-1 && outslot!=-1` → None；② meta != Pointer → None；
  ③ `inslot == -1` → None；④ `propagate_add_in2out(alttype, factory, op, inslot)`。
- `CPUI_PTRADD`：① `inslot==2 || outslot==2` → None；②①同上；③同上；④同上
  （typeop.cc:2268-2281）。
- `CPUI_INT_ADD`（typeop.cc:1181-1201 全量，替换现有简化）：非指针 int/uint 且
  `outslot==1 && in(1).is_constant()` 才放行；`outvn.is_constant() && meta!=Pointer`
  → `Some(alttype.clone())`；指针同上四步（经 propagateAddIn2Out）。
- `CPUI_INT_SUB`：→ `None`（基类 typeop.cc:317 无覆写）。
- 删除"非 const 兄弟 input"指针正向传播分支（3978-3986）。

### 3.4 TypeFactory plumbing（caller 链）

`Self::propagate_type`（coreaction.rs:3925，静态）→ `propagate_type_edge`（3847）→
`propagate_one_type`（4088）→ `propagate_across_returns`（4240）→ `apply`（4343）。
沿链新增 `factory: &mut TypeFactory`（或 `Arc<RwLock<TypeFactory>>`）参数。工厂来源：
`fd.arch` 挂接的 Architecture-owned TypeFactory；无 arch 时回退
`TypeFactory::shared_default()`（typefactory.rs:2233）。**与既有租约约定的接法保持
一致**：exact-piece WIP 已确立"ActionNameVars 把 Architecture-owned TypeFactory 传下去"
的模式（HANDOVER §4），B1 复用同一访问方式，勿新造第二条工厂通道。

不建议在本片扩展 `TypeOp` trait 的 `propagate_type` 签名（会波及全部 30+ impl，
与 D1 租约冲突面扩大）；生产路径保持在 coreaction.rs 单点 dispatch，
typeop.rs 侧只新增共享自由函数 `propagate_add_in2out`。真实 TypeOp 虚 dispatch 归
`ACTION-INFERTYPES-DISPATCH-0001` 后继。

### 3.5 租约与 write-set（预计）

| 文件 | 改动 | 租约约束 |
|---|---|---|
| `src/typeop.rs` | 新增 `propagate_add_in2out`；修 IntAdd trait impl 的指针分支；可选：Ptrsub/Ptradd 加 propagate_type 覆写（推迟到虚 dispatch 片） | **必须等 D1（`TYPEOP-LOCALTYPE-DISPATCH-0001`）释放**；D1 WIP 在 worktree `agent/typeop-localtype-d1`，dirty 含 typeop.rs |
| `src/type_system/typefactory.rs` | 新增 `down_chain_virtual`；复核/修正 `down_chain` rel 版尾式 fallback（typefactory.rs:1935） | 当前无冲突租约（任务描述所写 `src/types.rs` 实为此文件） |
| `src/coreaction.rs` | 四 arm 拆分改写 + factory 参数链（§3.4） | 须与 exact-piece WIP、D2（CALL input local dispatch）**串行**（HANDOVER §5 顺序：D1 → exact-piece → D2 → B1/PTRSUB） |
| `docs/api/typeop.md`、`docs/api/coreaction.md`（及 type_system 对应 doc） | 同 commit 更新 | pre-commit 强制 |
| `tests/oracle/action_infertypes_ptrsub_downchain_1204.{cc,rs,metadata.json}`、`tools/run_action_infertypes_ptrsub_downchain_oracle.sh` | 双侧 fixture（§4） | 仿 `action_infertypes_ptrwidth_1204` 三件套 |

commit message 需含 `## Alignment Evidence`（本报告 §1 即四类语义底稿）+
`## Differential`（progressbarinit 三函数 A/B），且 `src/coreaction.rs` 属机制 B 白名单。
coreaction.rs 是否属机制 C 核心算法白名单——白名单列的是 `blockaction/coreaction`
（"Actions 影响输出"），**按白名单字面 coreaction 在列** → 还需独立复核 agent 出
`## Cross-Review: APPROVE`。

### 3.6 移植时必须逐行复核的两处既有存疑

1. **typefactory.rs:1935** `result.or(Some(orig_pointer))` vs Ghidra type.cc:2671
   直接返回递归结果（可 NULL）。若保留 fallback，`relOff` 命中 parent 内非字段偏移时
   Rust 会退回 parent 指针而 Ghidra 返回 NULL——直接影响 1243-1247 的 command==0
   退回 alttype 分支。按 oracle 修正。
2. **`get_sub_type` 返回值语义**：Rust `(Option<Datatype>, i64)` 值返回 vs Ghidra
   `Datatype* getSubType(int8&, int8*)` 指针 + 就地 off 重写；确认 Option::None 与
   NULL、new_off 写回时机（parOff 用重规范化前值）逐字一致（typefactory.rs:1999-2004
   看起来已对，复核确认）。

---

## 4. Fixture 设计建议

命名/结构仿 `tests/oracle/action_infertypes_ptrwidth_1204.{cc,rs,metadata.json}` +
`tools/run_*_oracle.sh`：C++ 侧在锁定 12.0.4 源码树上直接调
`TypeOpPtrsub::propagateType` / `TypeOpIntAdd::propagateAddIn2Out`（构造 TypeFactory、
ProgressData 布局 struct、PcodeOp/Varnode），Rust 侧同输入调
`propagate_add_in2out`，输出**归一化投影**（不比较临时 ID）：command、consumed offset、
结果类型链（metatype/size/wordsize/ptrto 名/rel-parent 名/rel-offset/stripped 有无/
NULL）。metadata 记 oracle commit `e40ed130…`、source_blobs、输入指纹。

双侧观察面矩阵（每行一个 case，全部记录 propagateType 返回 + typeOrder 接受后的
最终 temp type）：

| Case | 输入 | 预期观察面 |
|---|---|---|
| F1 字段命中 | `ProgressData *`（如 total@8, long），PTRSUB in1=8 | 输出 = `long *`（strip-array 后字段 pointer）；off 重规范化为 0；par=ProgressData* parOff=8 → **ephemeral PointerRel(long*, parent=ProgressData, off=8)** |
| F2 非字段偏移 | PTRSUB in1=5（落在字段内部） | getSubType 返回字段+剩余 off？——按 Ghidra 语义：命中包含字段则返回该字段类型且 off=剩余；真正无组件命中（空洞）→ pointer NULL + parent 存在 → `PointerRel(unknown1, parent, 5)` |
| F3 offset==0 | PTRSUB in1=0 | command=0；downChain off=0 → struct 首字段指针；若全灭退回 alttype |
| F4 边界 off==size | PTRSUB in1=sizeof(ProgressData) | allowWrap=false → downChain NULL → pointer NULL → command=1 → **返回 NULL（None）** |
| F5 负编码偏移 | PTRSUB in1=0xfffffffffffffffc（→ i64 -4） | wrap 分支、PTRSUB 不允许 → None（INT_ADD 同偏移对照：允许 wrap，sign_extend%size 回绕） |
| F6 多层链 | `ProgressData[4] *`，PTRSUB in1=24（跨 array→element→field 两层 downChain） | do-while 两轮，中间 off 重规范化；最终字段 pointer + rel parent 链 |
| F7 Passthrough | PTRADD 非 const 索引、mult 整除 sz | command=3 → 返回 alttype 原样（无 downChain 调用——用工厂 intern 计数/类型 Arc 身份证明未新建） |
| F8 INT_SUB 指针 | 同 F1 输入但 op=INT_SUB | **None**（基类无覆写）——regression 守护 §3.3 改写 |
| F9 spacebase | in(inslot) 为 stack spacebase 指针 | ptrto==TYPE_SPACEBASE → 改写为 unknown 基类型 pointer（size/wordsize 取结果） |
| F10 rel 输入再传播 | 输入为 F1 产物的 PointerRel，再 PTRSUB | 虚分派到 rel 版 downChain（type.cc:2656）：越 parent 界 → None；relOff==0&&offset!=0 → parent 指针 |

验收门禁（每原子片）：
1. fixture 双侧逐字节 MATCH（runner exit 0，stdout SHA 相等）。
2. 三函数 A/B：
   `python3 tools/compare_ghidra.py <fresh.c> tests/golden/ghidra_curl_1204.c --func progressbarinit -v`
   （另跑 hugehelp/my_fwrite 守护零回归）；预期 progressbarinit 的 `->total` 层链
   开始正确收缩/取字段（完整闭合还需 STOP 片，勿单方面宣称完成）。
3. 全量 curl 差分 `--summary-only`，defects 变化逐条绑定 TODO ID（挂
   `TYPE-PTRWIDTH-PTRSUB-0001` 后继片或新 ID `TYPEOP-PTRSUB-DOWNCHAIN-0001`）。
4. 门禁健康四件套（check_gate_health / check_ghidra_annotations / check_ghidra_refs
   / check_alignment_evidence dry-run）。

风险提示：F1 的 par/parOff 行为意味着**即使字段命中，结果也是 PointerRel**（不是纯
字段 pointer）——这是 Ghidra 1241 的无条件行为（只要 parent 非空）；Rust 侧
`get_type_pointer_rel_ephemeral` 的 intern/`mark_ephemeral` 路径必须经 F1/F2/F10
覆盖。另注意 edge 前置 `resolveInFlow`（coreaction.cc:5081-5084）对 needsResolution
的 PointerRel 输入是真实前置变换，B1 fixture 的 C++ 侧若绕过 propagateTypeEdge 直接
调 propagateType 则观察不到——建议至少一个 case 从 `propagateTypeEdge` 层进（与
ACTION-INFERTYPES-DISPATCH-0001 的边界协商，避免两片互相借道）。

---

## 5. 结论浓缩

- **根因**：coreaction.rs:3970-3991 四 opcode 合并 arm 把指针原样 clone 传播，绕过了
  Ghidra propagateAddIn2Out→downChain 的 offset 消耗变换；已移植的 down_chain/
  down_chain_pointer/propagate_add_pointer 零生产 caller。
- **方案要点**：typeop.rs 新增 `propagate_add_in2out`（含 ephemeral getTypePointerRel、
  do-while 多层下降、PTRSUB 禁 wrap、spacebase 改写）+ typefactory.rs 新增
  `down_chain_virtual` 虚分派（并按 type.cc:2671 修正 rel 版尾式 fallback）+
  coreaction.rs 四 arm 拆分（INT_SUB → None、删 sibling 传播）+ factory 参数沿
  propagate_one_type→edge→propagate_type 链下传。
- **租约**：typeop.rs 等 D1 释放；coreaction.rs 与 exact-piece WIP/D2 串行；
  write-set = `src/typeop.rs`、`src/type_system/typefactory.rs`、`src/coreaction.rs`
  + 配对 docs + `action_infertypes_ptrsub_downchain_1204` 三件套。
- 机制 B/C 门禁适用（coreaction 在白名单，需 Differential + Cross-Review 块）。
