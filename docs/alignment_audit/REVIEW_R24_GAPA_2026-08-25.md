# R24 — 机制 C 独立复核：RETURNFOLD-GAPA-PROTOTYPES-0001

- 复核对象: `181aa4c8`（align: port ActionPrototypeTypes output-locked direct-attach branch, GAP-A）+ `2ab3eef1`（test: bilateral fixture + locked oracle runner）
- 集成身份确认: 两 commit 与 master 上 `4d300337`/`b6c93ae6` patch-id 逐字节相同（rebase 集成，无内容漂移）；`4d300337:src/coreaction.rs` blob `cb0047e6` == `181aa4c8:src/coreaction.rs` blob，fixture 证据与 master HEAD 代码一致。
- 复核方式: 只读主仓；独立打开 Ghidra 锁定 oracle（HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`，cpp subtree tree `b02e230a`，均与 metadata pin 一致）逐行研读，未采信实现 agent 的 Alignment Evidence 声明。禁 cargo，双侧运行结论以 metadata + runner 锁定 hash 的自洽性核验。

## Cross-Review: APPROVE

（附 1 项非阻断流程跟进，见 §6。）

---

## 1. Ghidra 源码独立研读（本 session 全文读）

### coreaction.cc:4609-4704 `ActionPrototypeTypes::apply`
- `iterend = data.endOp(CPUI_RETURN)` 在 strip 循环**之前**捕获（cc:4621）；strip 循环只 `opSetInput(slot0)` 不增删 RETURN，区间在 locked 循环中仍有效 —— 实现侧声明核实成立。
- output-locked 分支（cc:4637-4649）逐行：
  ```cpp
  if (data.getFuncProto().isOutputLocked()) {
    ProtoParameter *outparam = data.getFuncProto().getOutput();
    if (outparam->getType()->getMetatype() != TYPE_VOID) {
      for(iter=data.beginOp(CPUI_RETURN);iter!=iterend;++iter) {
        PcodeOp *op = *iter;
        if (op->isDead()) continue;
        if (op->getHaltType() != 0) continue;
        Varnode *vn = data.newVarnode(outparam->getSize(),outparam->getAddress());
        data.opInsertInput(op,vn,op->numInput());
        vn->updateType(outparam->getType(),true,true);
      }
    }
  }
  else
    data.initActiveOutput();
  ```
- else 臂（cc:4650-4651）**无条件** `initActiveOutput()`，与返回类型 voidness 无关。函数结尾 `return 0;`。
- 管线位置: `ActionPrototypeTypes("protorecovery")` 注册于 cc:5483（universal RestartGroup 顶层、mainloop 之前）；`ActionConditionalConst("analysis")` 注册于 cc:5676（actmainloop 内）——GAP-A 早挂 / GAP-B 晚读的先后链与 oracle 一致。

### funcdata_varnode.cc:148-169 / 239-247
- `newVarnode(s,base,off)`（cc:239-247，funcdata.hh:284 声明）= 委托 `newVarnode(s, Address(base,off))`。
- 展开体（cc:148-169）四腿顺序: `ct==0 → getBase(s,TYPE_UNKNOWN)` → `vbank.create(s,m,ct)` → `assignHigh(vn)` → `if (s>=minLanedSize) checkForLanedRegister(s,m)` → `queryProperties → setSymbolProperties / setFlags(vflags & ~typelock)`。

### op.hh:170-172 `getHaltType`
```cpp
uint4 getHaltType(void) const { return (flags&(PcodeOp::halt|PcodeOp::badinstruction|PcodeOp::unimplemented|
                                    PcodeOp::noreturn|PcodeOp::missing)); }
```
五值掩码确认。

### varnode.cc:474-495 `updateType(ct,lock,override)`
- `TYPE_UNKNOWN → lock=false`；`isTypeLock && !override → return false`；`(type==ct && isTypeLock()==lock) → return false`；清/设 typelock；`type=ct`。

### fspec.cc 输出存储分配链（ANN-F 桥的 oracle 侧）
- `FuncProto::setPieces`（cc:3843-3852）→ `updateAllTypes`（cc:4194-4224）→ `model->assignParameterStorage`（cc:2429）→ `ParamListStandardOut::assignMap`（cc:1568-1581）: 非 VOID outtype 走 `assignAddress(proto.outtype,…)` 从 output ParamEntry 组取槽。对单 output entry 的默认模型（x86-64 SysV: RAX = register:0x0），分配地址 = entry (space,base)。void outtype 则 `res.back()` 地址留 invalid（cc:1575-1578），cc:4639 门直接跳过。

## 2. 四类语义核对（复核清单 1）

| 语义类 | Ghidra（独立读出） | Rugra（src/coreaction.rs:6068-6144，独立读出） | 判定 |
|---|---|---|---|
| 引用/输出参数 | `outparam` 只读 const 访问；`vn` 每 RETURN 全新自由 varnode，跨 RETURN 不共享；`updateType` 原地写 vn | `out_type = fd.funcp.return_type.clone()`（读）；每 RETURN `fd.vbank.create_with_space(out_size,out_space,out_base)` 新 Arc 实例；`vn.write().update_type_lock(out_type,true,true)` 写各自实例 | MATCH |
| 循环边界/遍历顺序 | `beginOp(CPUI_RETURN)..iterend`，PcodeOpTree 地址升序；`isDead`/halt 命中仅 continue | 复用 strip 前拍摄的 `return_ops` 快照（alivelist 按 RETURN 过滤）；`is_dead` + 五值 halt continue 不中断；strip 不增删 RETURN，快照区间有效性与 oracle iterend 复用同构 | MATCH（含 §5.2 已声明近似注记） |
| 计数器/累加器 | 无计数器；onceperfunc 整体一次 | 无计数器；`RULE_ONCEPERFUNC`（get_flags）保持 onceperfunc | MATCH |
| 排序/比较键 | 无排序；序敏感点仅 opInsertInput 槽位= `op->numInput()`（追加末槽，既有值输入后移不替换）与地址序决定 create_index 方向 | `fd.op_insert_input(ret_op,vn,num_input())`；op_insert_input 实现（funcdata.rs:1748-1779）split_off+set_input+extend tail，slot==len 时纯追加；fixture b2 钉 nin=3、in1=register:0x40:4 不动；orderA b1_lt_b2=1 钉 create_index 递增 | MATCH |

逐项细核：
- **追加末槽 opInsertInput（非替换）** — fixture retA b2: nin=3、in1（既有 V=register:0x40:4, def=input）原样保留，in_last=register:0x0:4。双侧一致。✓
- **halt 掩码完整五值** — Rugra 逐位检查 `HALT|BADINSTRUCTION|UNIMPLEMENTED|NORETURN|MISSING`（op.rs:1<<21..25），与 op.hh:170-172 掩码集合相同。fixture b3halt 钉 nin=1 跳过。✓
- **updateType(type,true,true)** — `update_type_lock`（varnode.rs:1335-1358）与 varnode.cc:474-495 逐行对应：Unknown→unlock、isTypeLock&&!override→false、`Arc::ptr_eq` 同型比较（Ghidra 是 Datatype 指针比较，等价）、清/设 TYPELOCK。fixture typelock=1、mt=int。✓
- **void-locked 不动** — Void 门（cc:4639）跳过循环，且 locked 臂不走 else → 不 attach 也不 initActiveOutput。Rugra `if output_type_locked { if != Void { … } }` 同构，Scenario B active=0、nin=1。✓
- **unlocked else 臂** — `else { fd.init_active_output(); }` 无条件，Scenario C active=1、nin=1（无 attach）。✓
- isDead 守卫（cc:4642）保留，Scenario b4dead nin=1。✓
- newVarnode 四腿内联顺序 create→assign_high→check_for_laned→set_varnode_properties 与 cc:148-169 一致；`out_size >= fd.min_laned_size` 守卫同 `s >= minLanedSize`；min_laned_size 初值 u32::MAX 双侧（fixture 4 字节）均不触发 laned 腿。✓

## 3. ANN-F 地基桥等价性（复核清单 2）

- Oracle 侧: `outparam->getAddress()` 由 setPieces→updateAllTypes→`ProtoModel::assignParameterStorage`（fspec.cc:2429）→`ParamListStandardOut::assignMap`（fspec.cc:1568-1581）从模型 output ParamEntry 填充；单 output entry 默认模型给出 register:0x0。
- Rugra 侧: `ProtoModel::default_x86_64().output_entries[0]` = `ParamEntry{space:Register, base:0x0, size:8,…}`（protomodel.rs:119-122），fallback (Register,0) 与之一致。`out_size = out_type.get_size()`（类型尺寸）而非 entry 全宽 8——与 `outparam->getSize()`（= type->getSize()）一致。fixture 钉死 in_last=register:0x0:4 双侧一致。
- 结论: 单 output entry 情形下与 oracle assignParameterStorage **行为等价**（同一可观察地址/space/size）；multi-entry 模型（多寄存器返回）为显式 UNTESTED residual（`case_multi_output`，metadata coverage.multi_output），已正确不宣称覆盖。
- `Funcdata::new_varnode` 钉死 Ram space 因此内联 (s,AddrSpace,off) 形态——与 funcdata_varnode.cc:239-247 委托 + cc:148-169 展开一致，且 GAP-B copyBeforeRet 同款模式（既有先例）。

## 4. GAP-B 协同确认（复核清单 3）

- 管线顺序证实: prototypetypes（cc:5483，RestartGroup 顶层）先于 condconst（cc:5676，mainloop 内）。
- ConditionalConst 的 RETURN 臂（Rugra coreaction.rs:8744-8787 ↔ Ghidra cc:4439-4448）通过 `slot_of_input(&var_vn)` 定位本分支早挂的 varnode，copyBeforeRet COPY 输出落在 varVn 精确 (space,offset,size)（`create_def_with_space` + 三腿），`op_set_input(op,out,1)` 替换 slot 1。GAP-A 提供的正是该 varVn 的挂载点；两臂写同一 slot 但先后分明（early attach → heritage → late const fold），无冲突，与 oracle 顺序一致。✓

## 5. 双侧 fixture 14 行 MATCH 自洽（复核清单 4）

- 结构: schema=1 + preA + retA×4 + orderA + preB + postB + preC + postC + case×3 = **14 行**，与 metadata records=14 / bytes=1233 自洽；双侧输出语句逐行同构（格式串逐字核对: preA/retA/orderA/preB/postB/preC/postC/case 三行）。
- 驱动面: 双侧均调用**生产** `ActionPrototypeTypes::apply`（C++ 公有未改；`#define private public` 仅用于置 halt/dead 标记，沿用已复核 gapb fixture 模式）。
- pin 校验（本 session 独立 sha256/rev-parse，全过）:
  - `tests/oracle/returnfold_gapa_1204.cc` = `82e31a46…` ✓，`.rs` = `84a7a5ac…` ✓，`tools/run_returnfold_gapa_oracle.sh` = `ea684989…` ✓（与 metadata comparand 三 sha 一致）
  - `181aa4c8:src/coreaction.rs` 内容 sha256 = `62a18726…` ✓（metadata base_source_sha256）
  - oracle HEAD = `e40ed130…` ✓、cpp subtree tree = `b02e230a…` ✓
  - runner 内置 expected stdout/stderr/diff sha 锁定 + comparand/overlays 校验段（runner.sh:108-113, 222-224, 289-292）存在
- metadata: ghidra/rugra 双侧 stdout sha 同为 `81560905…`、diff exit 0、各 2 次确定性；`rc=0`（Ghidra `return 0` ↔ Rugra `NO_CHANGE=0`，action.rs:2222 核实）。
- residuals 诚实: `case_model_glue`/`case_multi_output`/`case_e2e_fold` 三行 UNTESTED 直接到 stdout；FSPEC-0001/FSPEC-0002 已在 docs/TODO_BOARD.md 登记（L633-634）。

## 6. 发现（均非四类语义 MISMATCH，不阻断）

1. **[流程跟进] residual ID `RETURNFOLD-GAPA-UPSTREAM-0001` 未登记 docs/TODO_BOARD.md**。全仓 grep 仅存在于 fixture metadata。按铁律 3（残差必须绑定登记的 TODO ID），建议在 TODO_BOARD 补一行（e2e return-value fold 链: MarkExplicit/MarkImplied/PrintC，依赖 GAP-D 与 print-stage fixture）。FSPEC-0001/0002 已登记，此项遗漏。
2. **[已声明近似注记] 遍历顺序**: Rugra 用 alivelist 快照（op 创建序）替代 Ghidra PcodeOpTree 地址序。本 Action 执行点（cc:5483，mainloop 之前）RETURN 未经历死而复生/重排，两序一致；若未来有 op 复活场景（重插入 append 到 alivelist 尾部而 optree 按地址插回），两序可能偏离——属 alivelist 基础设施既有近似，非本 commit 引入，fixture orderA 已钉当前行为。
3. **[可读性] coreaction.rs:6022-6032 变量名 `in0_is_const` 实存 `!is_constant()`（语义反转命名）**，外加 `in0_size > 0` 防御分支（Ghidra 直接解引用 inrefs[0]）。行为一致（正常输入下 slot0 恒存在），建议后续改名 `in0_not_const`。
4. **[既有基础设施] `set_varnode_properties` 的 symbol_table 平表按 offset 查询**未区分 space（Ghidra queryProperties 用完整 Address）。register:0x0 若撞上 ram 域同名 offset 符号会误设 MAPPED——fixture 双侧 symbol 表为空均 no-op，非本 commit write-set。

## 7. 判定

四类决定性语义（引用/遍历/计数/排序槽位）逐项独立核对无 MISMATCH；追加末槽、五值 halt 掩码、updateType(true,true)、void-locked 静默、unlocked else 臂五要点全部与锁定 oracle 逐行对应；ANN-F 桥在单 output entry 域内与 assignParameterStorage 行为等价；GAP-B 协同顺序由 cc:5483/cc:5676 管线位置证实；双侧 fixture pin 全部独立复验通过。

**Cross-Review: APPROVE**
