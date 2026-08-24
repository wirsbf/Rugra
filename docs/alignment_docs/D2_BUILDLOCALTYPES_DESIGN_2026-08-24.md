# B5-D2 设计审计 — ActionInferTypes::buildLocaltypes 的 CALL input TypeOp local dispatch

任务 ID: `TYPEOP-LOCALTYPE-DISPATCH-0001` / D2 caller 阶段
Oracle: Ghidra 12.0.4 tag `Ghidra_12.0.4_build`, commit `e40ed13014025f82488b1f8f7bca566894ac376b`
仓库: `/home/wirs/DEV/Rugra`（只读审计，未修改任何文件，未运行 cargo）
日期: 2026-08-24

---

## 1. Ghidra D2 语义全景

### 1.1 调用链与核心函数（签名逐字摘录）

```
coreaction.cc:5374  int4 ActionInferTypes::apply(Funcdata &data)
coreaction.cc:5008  void ActionInferTypes::buildLocaltypes(Funcdata &data)
varnode.cc:900      Datatype *Varnode::getLocalType(bool &blockup) const
op.hh:251-252       Datatype *outputTypeLocal(void) const { return opcode->getOutputLocal(this); }
                    Datatype *inputTypeLocal(int4 slot) const { return opcode->getInputLocal(this,slot); }
typeop.cc:261       Datatype *TypeOp::getOutputLocal(const PcodeOp *op) const        // 基类默认
typeop.cc:271       Datatype *TypeOp::getInputLocal(const PcodeOp *op,int4 slot) const
typeop.cc:687       Datatype *TypeOpCall::getInputLocal(const PcodeOp *op,int4 slot) const   // ★ D2 主目标
typeop.cc:720       Datatype *TypeOpCall::getOutputLocal(const PcodeOp *op) const
typeop.cc:745       Datatype *TypeOpCallind::getInputLocal(const PcodeOp *op,int4 slot) const
```

`buildLocaltypes`（coreaction.cc:5008-5037）本身**不遍历 op 列表**。它按
`data.beginLoc()..endLoc()` 的 VarnodeLocSet 顺序（space,offset,size,create-index 排序）
遍历 varnode，对每个 varnode 调 `vn->getLocalType(needsBlock)`；local dispatch 发生在
`Varnode::getLocalType` 内部：

1. `isTypeLock()` → 直接返回 `type`（varnode.cc:906-907）。
2. `def != 0` → `ct = def->outputTypeLocal()`，即**定义 op 的 getOutputLocal**（:911）。
3. 若 `def->stopsTypePropagation()` → `blockup = true; return ct;`（:912-915，提前返回，
   descendants 不再咨询）。
4. 否则对 `descend` 列表（`list<PcodeOp*>`，push_back 插入序 = 读绑定序）逐个
   `newct = op->inputTypeLocal(op->getSlot(this))`（:921-924），以
   `0 > newct->typeOrder(*ct)` 严格小于取最具体（:926-931，**平局保留先遇**）。
   **CALL input 播种就发生在这里**：varnode 作为某 CALL 的实参时，该 CALL 的
   `TypeOpCall::getInputLocal` 参与最小化竞争，与 def 的 getOutputLocal、以及其他
   descendant 的 getInputLocal 竞争。
5. `ct == 0` → `throw LowlevelError("NULL local type")`（:933-934）。
6. 回到 buildLocaltypes：`needsBlock` 为 true → `vn->setStopUpPropagation()`（:5030-5031），
   最后 `vn->setTempType(ct)`（:5035）。

另有一条与 D1/exact-piece 相邻的分支（coreaction.cc:5021-5027）：varnode 挂在
type-locked 父符号 SymbolEntry 上时先 `typegrp->getExactPiece(symType, curOff, size)`，
解析失败或 UNKNOWN 才回落 `getLocalType` — 该分支属
`TYPEFACTORY-EXACTPIECE-CALLERS-0001` 范畴，不是 D2 write-set。

### 1.2 哪些 op 类型走 local dispatch（12.0.4 全量清单）

基类默认（typeop.cc:261-275）：`getBase(size, TYPE_UNKNOWN)`。
中间类：TypeOpBinary/Unary/Func 按 `metain/metaout` 字段取 `getBase(size, meta)`（:323-375）。

覆写入口（.cc 行号 = 函数定义起始行）：

| Op | getInputLocal | getOutputLocal | 语义要点 |
|---|---|---|---|
| CBRANCH | typeop.cc:609 | — | slot1=bool；slot0=code ptr（wordsize 取自 in0 space） |
| **CALL** | **typeop.cc:687** | typeop.cc:720 | ★ 见 1.3 |
| **CALLIND** | **typeop.cc:745** | typeop.cc:776 | ★ 见 1.3 |
| CALLOTHER | typeop.cc:855 | typeop.cc:865 | 委托 `UserPcodeOp::getInputLocal/getOutputLocal`（userop.cc） |
| RETURN | typeop.cc:901 | — | slot>=1 = 本函数 FuncProto output type（VOID 或 size 不符→默认） |
| INT_LEFT/RIGHT/SRIGHT | :1510/:1535/:1600 | — | slot1=`getBaseNoChar(size,TYPE_INT)`，slot0 走 Binary |
| INDIRECT | typeop.cc:1992 | — | slot>=1 = code pointer（wordsize 取自被指向 op 的 space） |
| PTRADD | typeop.cc:2232 | typeop.cc:2238 | 双向均 TYPE_INT（等同 INT_ADD） |
| PTRSUB | typeop.cc:2314 | typeop.cc:2308 | 双向均 TYPE_INT |
| CPOOLREF | typeop.cc:2465 | typeop.cc:2451 | output 查 CPoolRecord（instance_of→bool）；input=INT |
| INSERT/EXTRACT | :2535/:2550 | — | slot0=UNKNOWN，其余走 Func |
| userop.cc: DatatypeUserOp | userop.cc:76 | userop.cc:70 | 固定 in/out 类型表（slot-1 偏移，前 4 槽） |
| userop.cc: VolatileReadOp | — | userop.cc:128 | 查全局 SymbolEntry getSizedType |
| userop.cc: VolatileWriteOp | userop.cc:159 | — | slot2 查全局 SymbolEntry getSizedType |
| userop.cc: InternalStringOp | — | userop.cc:361 | 返回 out vn 现有 type |

### 1.3 CALL / CALLIND 的决定性语义（D2 核心）

**TypeOpCall::getInputLocal（typeop.cc:687-718）逐字语义**：
- `vn = op->getIn(0)`；`slot==0` 或 `vn->getSpace()->getType()!=IPTR_FSPEC` → 直接
  `TypeOp::getInputLocal(op,slot)`（默认 UNKNOWN base）。
- 否则 `fc = FuncCallSpecs::getFspecFromConst(vn->getAddr())`（fspec 常量编码指针）。
- `ProtoParameter *param = fc->getParam(slot - 1)`（slot 从 1 起映射 param 0 起）。
- `param->isTypeLocked()`：`ct = param->getType()`，须
  `ct->getMetatype()!=TYPE_VOID && ct->getSize() <= op->getIn(slot)->getSize()`
  （**参数类型必须放得进实参 varnode**）→ 返回 ct。
- 否则 `param->isThisPointer()`：`ct` 为 `TYPE_PTR` 且 `ptrTo` 为 `TYPE_STRUCT` → 返回 ct
  （"this 指针视同 typelock"，源注释 :710-711）。
- 都不中 → 默认 UNKNOWN base。
- 源注释 :700-702 明示：slot↔param 同位假设是已知近似（giant-sized 参数未完善前的权宜）。

**TypeOpCall::getOutputLocal（typeop.cc:720-736）**：in0 非 FSPEC → 默认；
`!fc->isOutputLocked()` → 默认；output type VOID → 默认；否则返回 locked output type。

**TypeOpCallind 差异（typeop.cc:745-789）**：
- slot0 = code pointer：`getTypePointer(in0.size, codeType, op->getAddr().getSpace()->getWordSize())`
  （CALL 的 slot0 走默认 UNKNOWN，因 fspec 常量本身不进 local 竞争的种子面）。
- callspec 来源不同：`fc = op->getParent()->getFuncdata()->getCallSpecs(op)`（按 op 查
  qlst），不是 fspec 常量解码；`fc==0` → 默认。
- locked param 检查**只有 VOID 检查，没有 `ct->getSize() <= in(slot)->getSize()` 检查**
  （typeop.cc:764-765 vs CALL 的 :707）— **有意保留的不对称，fixture 必须覆盖**。
- this-pointer 分支同 CALL（:767-771）。
- getOutputLocal 同 CALL 逻辑但按 op 查 fc（:776-789）。

### 1.4 CALL input 播种时机与迭代/restart 语义

`ActionInferTypes`（coreaction.hh:960-981）：
- 构造 `Action(0,"infertypes",g)` — flags=0，非 onceperfunc；注册在 universal mainloop
  （rule_repeatapply 组，coreaction.cc:5508，位于 NonzeroMask:5507 之后、stackstall 组
  之前；:5504/5506 注释要求 DynamicMapping/Spacebase 先于 infertypes）。
- `reset()` 置 `localcount=0`。
- **12.0.4 无 `countMoves`**（全 cpp 源 grep 为空，任务书所指应为 `localcount`）。
- `apply`（coreaction.cc:5374-5416）恒返回 0，顺序为：
  1. `!data.hasTypeRecoveryStarted()` → return 0。
  2. `localcount >= 7`：恰在第 7 次 `warningHeader("Type propagation algorithm not settling")`
     + `setTypeRecoveryExceeded()` + `localcount+=1`（之后永远 no-op）。
  3. `data.getScopeLocal()->applyTypeRecommendations()`。
  4. **`buildLocaltypes(data)`** ← CALL input 播种在此（每次 mainloop 迭代的本轮 DFS 之前）。
  5. 全量 varnode（同过滤条件）`propagateOneType` DFS（:5172-5198，PropagationState 栈）。
  6. `propagateAcrossReturns`；spacebase 存在则 `propagateSpacebaseRef`。
  7. `writeBack` 有变化 → `localcount += 1`（注释 :5412 明示不计为 data-flow change）。
- restart 语义：自身返回 0 不触发组 restart；重入由 mainloop 内其他 Action 的变化驱动；
  发散保护即 localcount 上限 7。

### 1.5 与 stop-up flag 的交互（三层）

1. **PcodeOp::stop_type_propagation**（op.hh:115/215-217；varnode.cc:912-914）：
   def op 带此 flag 时 getLocalType 提前返回且 `blockup=true` — **descendants（含 CALL
   reader）的 getInputLocal 结果被整体丢弃**。设置点：PTRSUB 分裂规则族
   （ruleaction.cc:6517、6715、6753），清除点 ruleaction.cc:7098、7142。
   → CALL input 播种对这类 varnode 无效，且 varnode 被标记 stop-up。
2. **Varnode::stop_uppropagation**（varnode.hh:267/333；coreaction.cc:5030-5031）：
   buildLocaltypes 依 needsBlock 设置，varnode 级。
3. **propagateTypeEdge**（coreaction.cc:5093）：`outvn->stopsUpPropagation() &&
   outslot>=0` → return false — 其他边不能把类型传播进该 varnode。
   → CALL input varnode 一旦 stop-up，类型**冻结在 local seed**，本轮/后续轮 DFS 均无法改写。

### 1.6 四类决定性语义核对表

**buildLocaltypes（coreaction.cc:5008）**
- 引用/输出参数: `Funcdata &data` 引用共享；`needsBlock` 按引用出参；`setTempType`/
  `setStopUpPropagation` 突变 varnode（temp 字段 + addlflags）。
- 循环边界/遍历顺序: `beginLoc()..endLoc()` 单调前进，全函数 varnode loc 序
  （space,offset,size,create-index）；跳过 `isAnnotation`、`(!isWritten && hasNoDescend())`。
- 计数器/累加器: `bool needsBlock=false` **每 varnode 重置**；无跨 varnode 累加器。
- 排序/比较键: 无显式 sort；exact-piece 分支键 `curOff=(vn.off-entry.off)+entry.offset`；
  类型选择在 getLocalType 内 typeOrder。

**Varnode::getLocalType（varnode.cc:900）**
- 引用/输出参数: `bool &blockup` 只置 true 不复位（调用方负责初始化）；返回共享
  `Datatype*`（非拷贝）。
- 循环边界/遍历顺序: def op 先于 descendants；descend 列表 = 插入序（读绑定序），
  决定平局归属。
- 计数器/累加器: `ct` 初值 = def output 或 null；每 descendant 以严格更小 typeOrder 替换。
- 排序/比较键: `Datatype::typeOrder` 严格 `<`（`0>newct->typeOrder(*ct)`）。
- 异常: ct 仍 null → `throw LowlevelError("NULL local type")`。

**TypeOpCall::getInputLocal（typeop.cc:687）**
- 引用/输出参数: `const PcodeOp*` 只读；返回 canonical `Datatype*`。
- 循环边界/遍历顺序: 无循环；顺序敏感短路 = slot0/非 FSPEC 先判。
- 计数器/累加器: 无。
- 排序/比较键: `isTypeLocked` 优先于 `isThisPointer`；数值谓词 =
  `metatype!=VOID && size<=in(slot).size`；this 谓词 = `PTR && ptrTo==STRUCT`；
  fallback = `getBase(size, TYPE_UNKNOWN)`。

**ActionInferTypes::apply（coreaction.cc:5374）**
- 引用: `Funcdata &data`；`localcount` 成员跨 apply 持续、reset() 清零。
- 遍历: buildLocaltypes 与 propagate 循环同为 loc 序、同过滤。
- 计数器: `localcount` 仅在 writeBack 变化时 +1；7/7+1 单次警告。
- 比较键: 无（writeBack 内 `updateType` 返回是否变化）。

---

## 2. Rust 现状差异表（双侧行号）

Rugra 侧: `src/coreaction.rs` `build_localtypes`（:3651-3839）、`ActionInferTypes::apply`
（:4343-4444）；`src/typeop.rs` TypeOpCall/Callind（:1252-1319）。

| # | 语义点 | Ghidra | Rugra 现状 | 判定 |
|---|---|---|---|---|
| 1 | 遍历主体：varnode 中心 + def/descend 双向 | coreaction.cc:5016 + varnode.cc:910-932 | coreaction.rs:3665-3678（v_type 预播）+ 3681-3818（**op alivelist 遍历**） | 结构性差异（op 中心） |
| 2 | typeLock 早退 | varnode.cc:906-907（仅 locked 返回 type） | :3674-3676 任何 `v_type` 都预播 | 近似偏宽 |
| 3 | type-locked 父符号 exact-piece 分支 | coreaction.cc:5021-5027 | 无 | 缺失（exact-piece callers 租约范畴） |
| 4 | CALL/CALLIND **output** locked 播种 | typeop.cc:720-736/776-789 | :3727-3752 内联实现（有 locked+VOID 过滤），未走 typeop dispatch；`temps.insert` 覆盖式 | 部分对齐；merge 语义不符 |
| 5 | **CALL/CALLIND input param locked/this 播种** | typeop.cc:687-718/745-774 | **完全缺失** | **D2 目标** |
| 6 | CALLIND slot0 code pointer | typeop.cc:752-756 | 无 | 缺失 |
| 7 | RETURN slot>=1 = 本函数 output type | typeop.cc:901-922 | 无 | 缺失（登记，非 D2 必须） |
| 8 | CBRANCH slot0 code ptr | typeop.cc:616-618 | :3688-3693 仅 bool | 部分 |
| 9 | shift slot1 getBaseNoChar(INT) | typeop.cc:1510/1535/1600 | 无 | 缺失 |
| 10 | TypeOpBinary/Unary/Func metain/metaout | typeop.cc:323-375 | 无（:3696-3719 comparison/bool 臂部分替代） | 部分 |
| 11 | 默认 fallback = `getBase(size,TYPE_UNKNOWN)` | typeop.cc:264/274 | :4333-4340 `IntTypes::sized` 返回 **Int/Uint** | MISMATCH（typeOrder 序不同） |
| 12 | typeOrder-min 合并（严格<，平局先遇） | varnode.cc:926-931 | 各臂 `insert` 覆盖或 `or_insert` | MISMATCH |
| 13 | needsBlock / stop-up 三层交互 | varnode.cc:912-914; coreaction.cc:5030-5031/5093 | stop-up flag 不存在 | 缺失 |
| 14 | NULL local type 异常 | varnode.cc:933-934 | 无异常（必有 sized 兜底） | 缺失 |
| 15 | propagateTypeEdge `resolveInFlow` | coreaction.cc:5081-5084 | :3847-3919 无 | 缺失（D2 邻接） |
| 16 | apply 缺步：applyTypeRecommendations / propagateSpacebaseRef / setTypeRecoveryExceeded | coreaction.cc:5398/5407-5410/5393 | :4343-4444 均无（仅 warning） | 缺失 |
| 17 | localcount 7 上限 + 单次警告 | coreaction.cc:5390-5397 | :4352-4358 有 | 对齐 |
| 18 | temp type 存储 | varnode.hh:197-198 varnode 字段 | `HashMap vn_id → Arc<Datatype>`（:3615，已注明 RUGRA-GLUE） | 等价存储 |
| 19 | Rugra 专有 `seed_global_struct_pointers` | 无对应 | :4415 | 已登记 RUGRA-GLUE |
| 20 | typeop.rs 的 TypeOpCall/Cbranch/Callind/Return local getter 覆写 | typeop.cc 各处 | typeop.rs:1252-1319 均继承默认 `None`（trait 默认 :119-127） | **D1 缺口** |

D0 基础设施已就绪（D2 可直接消费）：
- `Varnode::call_spec: Option<Weak<RwLock<FuncCallSpecs>>>` + `get_call_spec()`（varnode.rs:149/216）；
- `Funcdata::get_call_specs_of_op`（funcdata.rs:1322-1359，fast path = in0 typed handle + owned/same-op 双校验，fallback = Ghidra 的 op-identity 扫描，非地址扫描）；
- `FuncProto::get_param(index) -> Option<&ProtoParameter>`（fspec.rs:333）、
  `ProtoParameter::{is_type_locked, is_this_pointer, data_type}`（fspec.rs:165-215）、
  `FuncCallSpecs.prototype.{output_type_locked, return_type}`（fspec.rs:1693/228/257）。

---

## 3. D2 集成设计

### 3.1 插入位置

`src/coreaction.rs` `build_localtypes` 的 op-walk 臂
`OpCode::CPUI_CALL | OpCode::CPUI_CALLIND`（当前 :3727-3752，只处理 output）。
在现有 output 播种之后扩展 input 播种（伪代码，最终以 D1 落地签名为准）：

```rust
OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
    // output 侧（现状保留，merge 语义见 3.2-b）
    ...
    // D2 新增：CALL inputs 经 TypeOpCall::getInputLocal local dispatch
    for slot in 1..op.num_input() {
        if let Some(ct) = typeop::dispatch(op).get_input_local(op, slot, &ctx) {
            merge_min_type_order(&mut temps, vn_id_of_in(op, slot), ct); // 见 3.2-b
        }
    }
}
```

注意与 Ghidra 的结构差异（差异表 #1）：Ghidra 的播种点是"遍历到 arg varnode 时经其
descendant CALL 竞争最小化"；Rugra 是 op 遍历。对 fixture 观察面等价的前提是
merge 采用 typeOrder-min（3.2-b），否则多 use 场景（fixture case6）必然分叉。

### 3.2 关键决策

a) **必须经 D1 dispatch，禁止 coreaction 内联复制参数锁逻辑。** D1（`src/typeop.rs`）
   落地 `TypeOpCall::get_input_local` / `TypeOpCallind::get_input_local` / Cbranch / Return /
   shifts / Func 系列覆写；D2 只做 caller。理由：分层对齐（Ghidra 的锁语义住在
   TypeOp 虚函数，print 阶段 getInputCast 也消费同一入口）；且 `USEROP-LOCALTYPE-METADATA-0001`
   的收尾要求 CALLOTHER→userop dispatch 走同一 caller 闭包。

b) **merge 语义 = typeOrder-min。** `entry().and_modify(|cur| if ct.type_order(cur) < 0
   { *cur = ct }).or_insert(ct)` — 对应 varnode.cc:926-931（严格 <，平局保留先播者）。
   现有 CALL-output 臂的 `temps.insert` 覆盖式建议同次统一为同一 helper（同一函数体内，
   write-set 已覆盖）。禁用 per-arm 覆盖，否则 fixture case6 暴露分叉。

c) **CALL vs CALLIND 不对称必须保留**（fixture case2 vs case5 的判别面）：
   - CALL: `param.size <= in(slot).size` 检查存在（typeop.cc:707）；
   - CALLIND: 无 size 检查，仅 VOID（typeop.cc:764）；且 slot0 = code pointer。
   - callspec 来源：CALL 走 in0 typed handle（等价 getFspecFromConst 路径）；CALLIND 走
     `fd.get_call_specs_of_op`（等价 `getCallSpecs(op)`）。D1 需两条路径或统一 ctx。

d) **fallback 约定。** D1 的 getter 应是全函数（含 `getBase(size,TYPE_UNKNOWN)` canonical
   fallback，由 Architecture-owned TypeFactory 出，TODO_BOARD:322 已约束"禁止地址扫描、
   字符串硬编码或 prototype snapshot 旁路"）。D1 返回 `Some(fallback)` 时 D2 直接 merge；
   若 D1 约定 `None`=走默认，D2 不得把 None 再喂给 `IntTypes::sized`（差异表 #11 的
   INT/UINT 误播会污染 typeOrder 竞争）。现有 trait 签名
   `fn get_input_local(&self, op:&PcodeOp, slot:usize) -> Option<Arc<Datatype>>`
   （typeop.rs:125）**不含 TypeFactory/Funcdata 上下文** — D1 必须先扩展签名（加 ctx
   参数）或给 TypeOp 实例注入 factory；D2 的实现绑定 D1 最终签名，本设计以
   `get_input_local(op, slot, ctx)` 记。

e) **stop-up 交互的降级登记。** Rugra 无 `stop_type_propagation`/`stop_uppropagation`
   flag（差异表 #13），D2 无法在本租约内补齐三层交互。fixture 在 Ghidra 侧观察
   `stopsUpPropagation()` 投影（case7），Rugra 侧预期恒 false — 该差异必须绑定新 TODO
   （建议 `VARNODE-STOPUP-FLAGS-0001`），fixture 状态只能记 MISMATCH/部分，不得宣称
   函数级 MATCH。

f) **write-set 边界。** D2 只改 `build_localtypes` 的 CALL/CALLIND 臂（+ §3.2-b 的
   merge helper）。不触碰 propagate_type_edge / apply 缺步（差异表 #15/16）— 那些属
   `ACTION-INFERTYPES-DISPATCH-0001` 链。`docs/api/coreaction.md` 同 commit 更新
   （pre-commit 强制）。

### 3.3 Fixture 设计（B2 双侧门禁）

命名: `tests/oracle/infertypes_callinput_local_1204.{cc,rs,metadata.json}` +
`tools/run_infertypes_callinput_local_oracle.sh`。
模板: harness 骨架照 `tests/oracle/action_infertypes_ptrwidth_1204.cc`
（FixtureTranslate/FixtureArchitecture + `fd.startTypeRecovery(); ActionInferTypes
action("typerecovery"); action.reset(fd); apply×2`），CALL 构造照
`tests/oracle/callspec_identity_lifecycle_1204.cc:124-127`
（`opSetOpcode(op,CPUI_CALL)` + `fd.newVarnodeCallSpecs(spec)`）。
metadata.json 记录 oracle commit `e40ed130…`、arch/compiler spec、输入 sha256。

场景矩阵（每个 case 一行观察记录）：

| case | 构造 | 判别目标 |
|---|---|---|
| 1 | CALL + param0 locked `int` (4B)，arg 4B | 播种 int4 → writeBack 后 arg v_type=int4 |
| 2 | CALL + locked param 8B，arg **4B** | CALL 的 size<=in 检查拒绝 → 默认（UNKNOWN 投影） |
| 3 | CALL + 未锁 this-pointer（PTR→STRUCT） | 播种 struct ptr（isThisPointer 等价锁） |
| 4 | CALL + locked VOID param | VOID 拒绝 → 默认 |
| 5 | CALLIND + locked param 8B，arg 4B | **无 size 检查** → 仍播种（与 case2 对照暴露不对称） |
| 6 | arg 同时喂 locked-param CALL 与 INT_ADD | typeOrder-min 决胜 + 平局先遇（merge 语义） |
| 7 | arg def = 手工 `setStopTypePropagation()` 的 PTRSUB | 播种被丢弃；`stopsUpPropagation()` 投影（Rugra 侧预期 false，登记差异） |
| 8 | CALL + 完全未锁 param | 默认 UNKNOWN base（校验 fallback 不落 INT/UINT） |

双侧观察面（两侧同构打印，逐字节可比）：
- `pre|` 每 arg vn：label、size、def opcode、flags、descendant 序（label 序列化）。
- `pass1|`/`pass2|`：apply 返回值、异常串、每 arg vn 的规范化类型
  （`metatype2string + size`，规范规则照 ptrwidth fixture :138-154）、
  `stopsUpPropagation()`、callspec identity 不变（`getType()==before` 类指针恒等投影）、
  descend 序不变、block 拓扑不变。
- 观察面以 writeBack 后 `getType()`（永久 v_type）为准 — temp type 是私有字段，
  ptrwidth/callspec fixture 的通行做法；"后续 pass 变化"用 pass1 vs pass2 的类型
  演化 + `types_stable` 投影覆盖。
- 判定：8/8 记录逐字节一致 → D2 观察面 MATCH（**仅限 CALL-input 播种路径**）；
  case7 的 stop-up 投影差异按 §3.2-e 登记，不冒充全函数 MATCH。

---

## 4. 租约与顺序

D2 write-set = `src/coreaction.rs` + `docs/api/coreaction.md` + fixture 三件套/runner
（`src/coreaction.rs` 与 `docs/api/coreaction.md` 是同一租约）。冲突域与最优排序：

1. **`TYPEFACTORY-EXACTPIECE-CALLERS-0001`**（TODO_BOARD:326，IN_PROGRESS）— 持有
   `src/coreaction.rs` 有限租约（ActionNameVars 消费 TypeFactory）。**D2 必须等其
   release 后串行进入**（任务书明示）。
2. **D1（`src/typeop.rs` + `docs/api/typeop.md`）** — 与 exact-piece callers 租约**无
   文件冲突，可立即并行开发**；D2 消费 D1 接口，D1 合入是 D2 的硬依赖。
3. **D3 producer/string**（TODO_BOARD:322，write-set 含 `src/coreaction.rs`）— D2 先于
   D3 进入：D2 改动收敛于 build_localtypes 单臂，风险小；D3 面积大（flow/arch/
   stringmanage/ruleaction/printc），先小后大降低 rebase 面。
4. `FUNCDATA-SCOPE-SYNC-0001`（REVIEW，coreaction 接线）— 复核只读，不构成写冲突，
   但集成 commit 需在其落地后 rebase 验证。
5. `VARNODE-LOCALTYPE-RESOLUTION-0001`（TODO_BOARD:346，依赖本 TODO 整体）— 将按
   varnode 中心结构**重写** getLocalType 数据流，会重构 build_localtypes 的骨架并
   吸收 D2 的 op 臂。因此 D2 必须**最小化、面向 D1 dispatch 接口编程**（不内联、
   不复制），使其被取代时只需删 caller 循环、fixture 观察面继续有效。
6. `ACTIONTYPEINFER-VTYPE-0001`（TODO_BOARD:343）依赖链末端，最后收口。
7. 顺带收益：D1 落地 CALLOTHER→userop dispatch 后，`USEROP-LOCALTYPE-METADATA-0001`
   （TODO_BOARD:332）的 "caller/fallback 闭包" 条件即满足，可在 D2 同 wave 复核解锁。

**最优排序**：
`TYPEFACTORY-EXACTPIECE-CALLERS-0001` 释放 ∥ D1 开发合入 → **D2（coreaction.rs 串行
独占）** → D3 → MERGE-PERSISTENCE-CHANNELS-0001 / USEROP-LOCALTYPE-METADATA-0001 复核
解锁 → VARNODE-LOCALTYPE-RESOLUTION-0001 → ACTION-INFERTYPES-DISPATCH-0001 /
ACTIONTYPEINFER-VTYPE-0001。

提交纪律：commit message 含 align/port 需附 `## Alignment Evidence`（引用 §1.6 表）；
coreaction.rs 不在机制 C 核心算法白名单（heritage/jumptable/blockaction/condexe/
varmap 核心/merge），故无强制 Cross-Review，但 `TYPEOP-LOCALTYPE-DISPATCH-0001` TODO
惯例为独立 review — 建议保留独立复核（fixture 判别力强，case2/5/6/7 均为方向性判别）。

---

## 5. 风险与红旗自查

- 🚩 现有 build_localtypes 是 op 中心结构，D2 只加 CALL input 臂时，**观察面对齐仅限
  fixture 矩阵**；全函数等价需 VARNODE-LOCALTYPE-RESOLUTION-0001。fixture 结论措辞
  必须"CALL-input 播种路径 MATCH"，不得写 "build_localtypes MATCH"。
- 🚩 `IntTypes::sized` 兜底（差异表 #11）若在 D2 路径上被触发（case8），会以 INT 参与
  typeOrder 竞争 — case8 的设计就是拦截这个；若 D1 fallback 未就绪而 case8 失败，
  正确动作是补 D1 fallback，不是放宽断言。
- 🚩 CALL/CALLIND callspec 查询路径不同（fspec const vs getCallSpecs(op)）；Rugra 侧
  统一走 `get_call_specs_of_op` 时，其 fast path 已要求 Iop+annotation+typed handle，
  对 CALLIND（in0 是真实指针 varnode）自然落 fallback op-identity 扫描 — 与 Ghidra
  语义一致，但 fixture case5 需覆盖 CALLIND 查询路径。
- 审计未修改仓库任何文件、未运行 cargo；本报告仅基于双侧源码阅读。
