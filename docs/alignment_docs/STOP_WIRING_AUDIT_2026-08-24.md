# B2 — STOP flag 接线方案（progressbarinit 7 层 `->total` 嵌套根因）

> 只读审计报告。Oracle：Ghidra 12.0.4 tag `Ghidra_12.0.4_build` commit `e40ed13014`。
> 仓库：`/home/wirs/DEV/Rugra`（未修改任何文件）。
> 现症证据：`result/curl_cur.c:1122/1126` — `(&(&(&(&(&(&(&bar->point)->total)->total)->total)->total)->total)->total)->total`，恰好 **7 层** `->total`，与 `ActionInferTypes` 的 7-pass cap 一一对应。

---

## 0. 结论摘要

Ghidra 的 STOP 机制是**两个不同 flag、三个阶段**的接力：

| 阶段 | flag | 载体 | 设置者 | 消费者 |
|---|---|---|---|---|
| ① Rule 层 | `stop_type_propagation = 0x40` | **PcodeOp.addlflags**（op.hh:115） | RulePtrArith/AddTreeState（ruleaction.cc:6517）、RuleStructOffset0（ruleaction.cc:6715、6753）；清除 ruleaction.cc:7098、7142 | **唯一消费者**：`Varnode::getLocalType`（varnode.cc:912） |
| ② 本地类型层 | `blockup`（引用出参） | 栈上 bool | getLocalType 自身设置 | `ActionInferTypes::buildLocaltypes`（coreaction.cc:5030） |
| ③ 传播层 | `stop_uppropagation = 0x800` | **Varnode.addlflags**（varnode.hh:131） | buildLocaltypes（coreaction.cc:5031，全 decompile 源码**只设不清**） | **唯一消费者**：`ActionInferTypes::propagateTypeEdge`（coreaction.cc:5093） |

Rugra 现状：①的 setter（裸 `addlflags |=`）与 getter 都存在，但 **getter `stops_type_propagation()` 全仓零调用**；②③ 完全缺失（`get_local_type` 是忽略 `_block_up` 的 stub；Varnode `addl_flags` 枚举在 0x400 截断，无 0x800）。因此 RuleStructOffset0 插入的 PTRSUB 边界对类型传播**完全不设防**：每轮 ActionInferTypes 把 struct-pointer 类型沿链多推一层，`writeBack` 每轮都变化 → `localcount` 连续 +1 → 7-pass cap 冻结 → 嵌套深度恰好停在 7。

---

## 1. Ghidra 侧 STOP 生命周期图（全部行号已对锁定 oracle 核实）

```
RulePtrArith / RuleStructOffset0
  ruleaction.cc:6517  AddTreeState::buildTree: if (size != 0) newop->setStopTypePropagation();   // PTRSUB 部分
  ruleaction.cc:6715  RuleStructOffset0 (isFormalPointerRel 分支, "pointer up to parent" PTRSUB)
  ruleaction.cc:6753  RuleStructOffset0 (TYPE_STRUCT/TYPE_ARRAY 分支, PTRSUB(ptr, 0))
        │  设置 op.addlflags |= 0x40  (op.hh:216)
        ▼
ActionInferTypes::apply  (coreaction.cc:5374, 每轮先跑)
  └─ buildLocaltypes  (coreaction.cc:5008-5037)
       按 VarnodeLocSet 地址序遍历; per-vn: bool needsBlock = false (cc:5020)
       └─ vn->getLocalType(needsBlock)   (varnode.cc:900-936)
            cc:906  isTypeLock → 直接返回锁类型（不触碰 blockup）
            cc:910  def != 0: ct = def->outputTypeLocal()        // TypeOp 虚派发
            cc:912  if (def->stopsTypePropagation()) {           // ★ 消费 op flag 0x40
            cc:913      blockup = true;                           // 只置 true，从不清 false
            cc:914      return ct;                                // 提前返回：跳过全部 readers
                     }
            cc:921-932  遍历 descend（std::list 插入序）:
                          newct = op->inputTypeLocal(i=op->getSlot(this))
                          ct = typeOrder 严格更小者；平手保留先见者
            cc:933  ct==null → throw LowlevelError("NULL local type")
       cc:5030-5031  if (needsBlock) vn->setStopUpPropagation();  // ★ op flag → varnode flag 0x800
       cc:5035       vn->setTempType(ct)
        ▼
  同一轮 apply 内：propagateOneType → propagateTypeEdge  (coreaction.cc:5074-5113)
       cc:5093  if (outvn->stopsUpPropagation() && outslot >= 0) return false;
                  // ★ 消费 varnode flag 0x800：封禁任何类型经 op 边流入该 varnode（作为输入槽目标）
  cc:5411  if (writeBack(data)) localcount += 1;   // 只有发生类型变化的轮才计数
  cc:5390  if (localcount >= 7) { ==7 时 warn "Type propagation algorithm not settling"
                                   + data.setTypeRecoveryExceeded(); localcount=8 } return 0;
```

清除路径（op flag 0x40，随 op 结构变换撤销）：
- ruleaction.cc:7098 `removeLocalAddRecurse`：PTRSUB→COPY 时 `op->clearStopTypePropagation()`；
- ruleaction.cc:7142 `RulePtrsubUndo::applyOp`：PTRSUB→INT_ADD 时清除。
- **varnode flag 0x800 全源码无任何 clear 调用点**（`clearStopUpPropagation` 声明于 varnode.hh:334，零引用），生命周期 = SSA varnode 生命周期。
- 克隆保留：funcdata_block.cc:968-970 的 addlflags 掩码**包含** `stop_type_propagation`（连同 special_prop/special_print/incidental_copy/is_cpool_transformed/store_unmapped）。

**对 7-pass cap 的精确影响**：cap 不是"跑 7 轮"而是"**累计 7 个类型变化轮**"。STOP 接线后，PTRSUB 输出的本地类型被钉在 `outputTypeLocal()`（PTRSUB → `getBase(size, TYPE_INT)`，typeop.cc:2308），且该 varnode 拒绝一切经边流入的类型 → 传播迅速到达不动点 → `writeBack` 返回 false → `localcount` 停增 → cap 不触发、无 "not settling" 警告、`setTypeRecoveryExceeded` 不置位（该位还会被 RulePtrArith/RuleStructOffset0 的 `isTypeRecoveryExceeded() → assignPropagatedType` 消费，ruleaction.cc:6505/6512）。未接线时每轮链上多一层指针类型 = 每轮 writeBack 必变 = 7 层后强制冻结 —— 与 curl_cur.c 的 7 层 `->total` 完全吻合。

其他核实到的 Ghidra 事实：
- `getLocalType` 的调用方**只有** buildLocaltypes 两处（coreaction.cc:5026/5029）。
- `ActionInferTypes::reset(Funcdata&) { localcount = 0; }`（coreaction.hh:969）——**按函数重置**。
- `ActionInferTypes::apply` 恒 `return 0`（cc:5412 注释掉 `count+=1`，不算 data-flow change）。

---

## 2. 四类决定性语义核对表（签名逐字摘录）

### 2.1 `varnode.cc:900` `Datatype *Varnode::getLocalType(bool &blockup) const`

| 类别 | Ghidra 语义 |
|---|---|
| 引用/输出参数 | `bool &blockup` 为引用出参：**只置 true 不清 false**（cc:913）；由调用方 per-iteration 重置（cc:5020 `bool needsBlock = false;`）。返回 `Datatype*`；cc:934 无类型时 **throw `LowlevelError("NULL local type")`**。 |
| 循环边界/遍历顺序 | `for(iter=descend.begin();iter!=descend.end();++iter)`（cc:921）：`std::list<PcodeOp*>` **addDescend 追加的插入序**，无跳过、无排序。 |
| 计数器/累加器 | 无计数器。累加器 `ct`：初值 = `def->outputTypeLocal()`（cc:911，def 存在时）或 null；descend 中 `if (0>newct->typeOrder(*ct)) ct = newct;`（cc:929）——**typeOrder 严格更小才替换**。 |
| 排序/比较键 | `Datatype::typeOrder`：值小者胜；**平手保留先见者**（不替换）。`i = op->getSlot(this)` 按 varnode 身份取槽位（cc:923）。 |

### 2.2 `coreaction.cc:5008` `void ActionInferTypes::buildLocaltypes(Funcdata &data)`（static）

| 类别 | Ghidra 语义 |
|---|---|
| 引用/输出参数 | `Funcdata&` 突变：`vn->setStopUpPropagation()`（cc:5031）+ `vn->setTempType(ct)`（cc:5035）；`typegrp = data.getArch()->types`（cc:5014）。 |
| 循环边界/遍历顺序 | `data.beginLoc()`→`endLoc()`：**VarnodeLocSet 地址序**（space→offset→size→def 序）。跳过：`isAnnotation()`（cc:5018）、`!isWritten() && hasNoDescend()`（cc:5019）。 |
| 计数器/累加器 | 无。`bool needsBlock` **每个 varnode 循环体内重置为 false**（cc:5020），作用域单 varnode。 |
| 排序/比较键 | 分支键：`entry!=0 && !vn->isTypeLock() && entry->getSymbol()->isTypeLocked()`（cc:5022）→ `typegrp->getExactPieces(symType, curOff, size)`；结果 null 或 `TYPE_UNKNOWN` → 退化 `getLocalType` 浮动（cc:5025-5026）。`curOff = (vn.addr - entry.addr) + entry.getOffset()`（cc:5023）。 |

### 2.3 `coreaction.cc:5074` `bool ActionInferTypes::propagateTypeEdge(TypeFactory *typegrp,PcodeOp *op,int4 inslot,int4 outslot)`（static）

| 类别 | Ghidra 语义 |
|---|---|
| 引用/输出参数 | 突变 `outvn->setTempType(newtype)`（cc:5109）；返回 bool（cc:5110 `return !outvn->isMark();`）。 |
| 循环边界/遍历顺序 | 无循环；**guard 顺序决定性**：cc:5085 `inslot==outslot` 回溯禁 → cc:5086-5091 outslot<0 取 out / 否则取 in 且 annotation 拒 → cc:5092 typelock 拒 → **cc:5093 `if (outvn->stopsUpPropagation() && outslot >= 0) return false;`** → cc:5095-5098 BOOL 且 NZMask>1 拒 → cc:5100 opcode `propagateType` 派发。 |
| 计数器/累加器 | 无。 |
| 排序/比较键 | cc:5107 `if (0>newtype->typeOrder(*outvn->getTempType()))` —— 与当前 temp 相比**严格更小**才写入。 |

### 2.4 `coreaction.cc:5374` `int4 ActionInferTypes::apply(Funcdata &data)`（cap 部分）

| 类别 | Ghidra 语义 |
|---|---|
| 引用/输出参数 | cap 分支突变 `data.warningHeader(...)` + `data.setTypeRecoveryExceeded()`（cc:5392-5393）。 |
| 循环边界/遍历顺序 | cc:5400 传播轮循 beginLoc 序（同 2.2 跳过条件）。 |
| 计数器/累加器 | `localcount`（成员，coreaction.hh:964）：**仅** cc:5411-5414 `if (writeBack(data)) localcount += 1;` 时递增；cap `>=7` 时 `==7` 分支内再 +1（=8，使警告只发一次）；**reset 按函数清零**（coreaction.hh:969）。 |
| 排序/比较键 | `localcount >= 7`（先判 >= 再判 ==）；"This constant arrived at empirically"（cc:5390 注释）。 |

### 2.5 flag 常量与访问器（逐字）

- op.hh:115 `stop_type_propagation = 0x40,	///< Stop data-type propagation into output from descendants`（位于 PcodeOp 第二个匿名枚举，存 `addlflags`，op.hh:124）
- op.hh:215-217：`bool stopsTypePropagation(void) const` / `void setStopTypePropagation(void)` / `void clearStopTypePropagation(void)`
- varnode.hh:131 `stop_uppropagation = 0x800,	///< Data-types do not propagate from an output into \b this`（位于 `addl_flags` 枚举，存 `addlflags: uint2`，varnode.hh:139）
- varnode.hh:267 `bool stopsUpPropagation(void) const`；varnode.hh:333/334 `setStopUpPropagation` / `clearStopUpPropagation`
- ⚠️ handover 所称 "varnode 侧 0x800" 正确，但须注意**主 `varnode_flags` 枚举里 0x800 是 `volatil`**（varnode.hh:93）——两个枚举同值不同义，Rugra 接线时必须落在 `addl_flags`（u16 `addlflags` 字段），不能混入主 flags。

---

## 3. Rust 接线方案

### 3.1 现状缺陷清单（本次审计核实，双侧行号）

| ID | 位置 | 缺陷 |
|---|---|---|
| W1 | `src/varnode.rs:103-115` | `addl_flags` 枚举止于 `SPACEBASE_PLACEHOLDER=0x400`，缺 `STOP_UP_PROPAGATION=0x800` 与 `HAS_IMPLIED_FIELD=0x1000`（varnode.hh:131-132）；无 set/clear/get 访问器（varnode.hh:267/333/334）。 |
| W2 | `src/varnode.rs:1421-1428` | `get_local_type` stub：忽略 `_block_up`、不取 `def` 的 output_local、不查 `stops_type_propagation`、不遍历 descend 的 input_local、无 typeOrder 归并、无 "NULL local type" 错误路径，直接 `return self.v_type.clone()`。 |
| W3 | `src/coreaction.rs:3651-3840` | `build_localtypes` 是 per-op match 的替代实现：从不调用 `get_local_type`、无 `needs_block`、从不 `set_stop_up_propagation`；cc:5022-5027 SymbolEntry/getExactPieces 分支整体缺失（varnode.mapentry 字段已存在于 `src/varnode.rs:141`，是可移植的）。 |
| W4 | `src/coreaction.rs:3846-3922` | `propagate_type_edge` 有 cc:5085 回溯/cc:5092 typelock/cc:5095-5098 bool-NZMask/cc:5107 typeOrder 严格小，**独缺 cc:5093 `stopsUpPropagation && outslot>=0` 拒绝**。 |
| W5 | `src/coreaction.rs:4352-4357` | cap 分支缺 `fd.set_type_recovery_exceeded()`（cc:5393）；funcdata.rs 全文件无 typerecovery_exceeded 访问器（仅 5896 行 doc 提及 clear 保留语义）。`impl Action for ActionInferTypes`（4343-4442）**无 `reset` override**（Ghidra coreaction.hh:969 按函数清零 localcount）。 |
| W6 | `src/funcdata.rs:8873-8875` | **错位近似**：volatile read type-locked 路径，Ghidra funcdata_varnode.cc:762 设 `PcodeOp::special_prop`（op.hh:109，值 1），Rugra 却设 `STOP_TYPE_PROPAGATION`。STOP 真正接线后这里会**虚假封锁** volatile guard 输出的类型传播，必须改回 special_prop 语义（若 op_addl_flags 缺 SPECIAL_PROP=1 一并补）。 |
| W7 | `src/ruleaction.rs:16391` | `AddTreeState::build_tree` PTRSUB 分支**无条件**设 STOP；Ghidra ruleaction.cc:6515-6517 有 `if (size != 0)` guard。 |
| W8 | `src/ruleaction.rs:16479-16481` | RuleStructOffset0 的 `isFormalPointerRel` 分支（含 cc:6715 的 setStopTypePropagation）整体省略（注释声明无 TypePointerRel）——已登记残差，非本 TODO write-set。 |
| OK | `src/op.rs:67/597-602` | `STOP_TYPE_PROPAGATION=0x40` + getter/clearer 与 op.hh 一致（缺专用 setter，现为裸 `|=`，建议补 `set_stop_type_propagation` 对齐 op.hh:216）。 |
| OK | `src/funcdata.rs:14050` | 克隆 addlflags 掩码含 STOP_TYPE_PROPAGATION，与 funcdata_block.cc:969 一致。 |
| OK | `src/ruleaction.rs:16517` | RuleStructOffset0 STRUCT/ARRAY 路径设 STOP（对应 cc:6753）；13629/13696 两个 clear 对应 cc:7098/7142。 |

### 3.2 接线步骤（自底向上）

**Step 1 — flag 常量补齐（src/varnode.rs）**
`addl_flags` 追加 `pub const STOP_UP_PROPAGATION: u16 = 0x800;` 与 `pub const HAS_IMPLIED_FIELD: u16 = 0x1000;`（`// Ghidra: varnode.hh:131-132`），并按 varnode.hh:267/333/334 加 `stops_up_propagation()/set_stop_up_propagation()/clear_stop_up_propagation()`。**不得**把 0x800 加进主 `varnode_flags`（那里 0x800=volatil）。

**Step 2 — `get_local_type` 完整移植（src/varnode.rs）**
按 2.1 的四类语义逐项落：
1. `is_type_lock()` → 返回锁类型（Ghidra 直接 `return type`）；
2. `def` 存在 → `ct = def 的 TypeOp::get_output_local`（typeop.rs 已有 28 处 `get_output_local/get_input_local` 派发，即 TYPEOP-LOCALTYPE-DISPATCH-0001 D1 产物）；
3. `def.stops_type_propagation()` → `*block_up = true; return ct;`（提前返回，跳过全部 readers——这是唯一消费者接线点）；
4. `descend`（`Vec<Weak<RwLock<PcodeOp>>>`，`src/varnode.rs:145`）按**插入序**遍历：`newct = op 的 get_input_local(slot)`，`ct` 以 `type_order` **严格更小**替换，平手保留先见；
5. 全空 → `Err(anyhow!("NULL local type"))`（对齐 cc:934 LowlevelError）。
借用注意：descend 元素是 Weak，逐个 upgrade；slot 判定用 Arc 指针身份（funcdata.rs 已有 `op_get_slot` 同款做法，varnode 方法内可内联同逻辑）。

**Step 3 — `build_localtypes` 接线（src/coreaction.rs）**
- 每个 varnode 循环体内 `let mut needs_block = false;`（cc:5020，作用域=单 varnode）；
- 补 cc:5022-5027 分支：`vn.mapentry`（`src/varnode.rs:141`）+ `!is_type_lock` + symbol `is_type_locked` → TypeFactory `get_exact_pieces`；null/UNKNOWN → 走 `get_local_type(&mut needs_block)`（get_exact_pieces 若缺，挂 TYPEFACTORY-EXACTPIECE-0001 依赖，不得静默跳过）；
- `if needs_block { vn.write().set_stop_up_propagation(); }`（cc:5030-5031）——现循环全程持 read 锁，需重构为 scoped write；
- `temps.insert(vn_id, ct)` 无条件覆盖（cc:5035 setTempType）；
- 现有 per-op seeding arms 的正确归宿是 TypeOp 虚派发（Ghidra 的 outputTypeLocal/inputTypeLocal 本身就是 typeop.cc 派发）：CALL 锁签名（typeop.cc:720-734）、LOAD/STORE 指针（TypeOpLoad 等）应随 D1 派发表补齐后从 build_localtypes 撤出；`seed_global_struct_pointers`（coreaction.rs:4451 起，RUGRA-GLUE）保留但注释其无 Ghidra 对应物，且不得覆盖 STOP 封禁的 varnode。

**Step 4 — `propagate_type_edge` 补 cc:5093（src/coreaction.rs）**
在 typelock guard（现 3887-3891 read-scope）之后、bool-NZMask guard 之前插入：
`if outslot >= 0 && ov.stops_up_propagation() { return None; }`（与 typelock 合并同一 read scope）。注意条件顺序：`outslot >= 0` 与 `stops_up_propagation` 的合取，outslot<0（目标是 op 输出）不受此 flag 拦截。

**Step 5 — `apply` 补全（src/coreaction.rs）**
- cap `==7` 分支补 `fd.set_type_recovery_exceeded()`（cc:5393；需 funcdata.rs 加位+访问器，见 Step 6）；
- 为 `impl Action for ActionInferTypes` 补 `reset`：`self.local_count = 0`（coreaction.hh:969，按函数）。

**Step 6 — 邻域修复（超出 B2 主 write-set，须另立 TODO/租约协调）**
- `src/funcdata.rs:8875`：STOP→`SPECIAL_PROP`（=1，op.hh:109）修正 + `typerecovery_exceeded` 位与访问器（`set_type_recovery_exceeded`/`is_type_recovery_exceeded`，消费者 ruleaction.cc:6505/6512 的 Rust 侧对应物）；
- `src/ruleaction.rs:16391`：补 `if self.size != 0` guard（ruleaction.cc:6515-6517）。

### 3.3 预计 write-set 与依赖

| 项 | 内容 |
|---|---|
| 主 write-set | `src/varnode.rs`（Step 1/2）、`src/coreaction.rs`（Step 3/4/5）；同 commit `docs/api/varnode.md`、`docs/api/coreaction.md`（pre-commit 强制） |
| 租约 | **阻塞于 D2（TYPEOP-LOCALTYPE-DISPATCH-0001 的 caller 段 = `src/coreaction.rs`）释放**；`src/varnode.rs` 与 `src/typeop.rs`（D1）无冲突可先行 |
| 邻域 TODO | funcdata.rs（W5 exceeded + W6 special_prop）、ruleaction.rs（W7 guard、W8 pointerRel 残差）、TYPEFACTORY-EXACTPIECE-0001（get_exact_pieces） |
| 核心算法白名单 | `src/coreaction.rs` 属机制 B 白名单 → commit 需 `## Alignment Evidence` + 独立 `## Cross-Review: APPROVE`；机制 B2 四态初始按 `UNTESTED`，oracle fixture 跑通前不得记 MATCH |
| 门禁 | E2E 后 `python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func progressbarinit -v`；全量 defects>0 须逐条绑定 TODO ID 的 `## Differential` 块 |

---

## 4. 验证设计（证明嵌套层数收敛）

### 4.1 逐函数双侧 fixture（机制 B2 主证据）
`tests/oracle/stopflag_localtype_1204.{cc,rs,metadata.json}` + runner，沿既有 paired-harness 模式：
- **图形状**：手工构造 4 组最小 P-code——(a) PTRSUB 带 STOP 输出喂 LOAD（LOAD 输出带 struct 类型）；(b) 同图但 STOP 未设；(c) PTRSUB 喂 STORE；(d) typelock 变体。同输入双侧运行。
- **观察域**：`getLocalType` 的 `(vn printRaw, 返回 type printRaw, blockup)` 三元组；`buildLocaltypes` 后的 `(vn, stop_up set?, temp type)`；`propagateTypeEdge(op, inslot, outslot)` 对 sealed varnode 的逐边返回值。Rust 侧临时观察用 `eprintln!`（stderr TAG），不污染 stdout。
- **判别力**：组 (a) 必须输出 `blockup=true` + temp=Base(Int, ptrsize) + 边拒绝；组 (b) 必须走 inputTypeLocal 归并。这证明**消费者语义**而非仅"flag 被读"。

### 4.2 逐轮 pass 收敛 fixture（证明 7 层→真层数）
- **oracle 侧**：以 `-DTYPEPROP_DEBUG=1` 编译锁定 oracle decompile（propagationDebug + apply 的 `"Type propagation pass - N"` 经 `printDebug` 落 console），对含链式 offset-0 struct 访问的迷你函数捕获逐轮 `(pass#, vn, newtype, from op/slot/init/alias)` 序列；
- **Rust 侧**：`[STEP]`-风格 stderr 每轮 dump 同构三元组（varnode 以规范化 nonce 键）；
- **收敛断言**：接线后 PTRSUB 输出 temp 类型序列从 pass 1 起恒定（零增长），对照（未接线基线）为每变化轮 +1 层；`localcount` 终值 < 7、无 "not settling" 警告、`is_type_recovery_exceeded()==false`；最终 C 文本 `->total` 深度 == oracle 深度。

### 4.3 E2E 差分门禁（机制 B）
`cargo run --release --example curl_decompile` → `--func progressbarinit` 对 `tests/golden/ghidra_curl_1204.c`：curl_cur.c:1117-1126 的 7 层嵌套行必须塌缩到 oracle 形态；随后全量 `--summary-only`，任何 defects/numbering 残差逐条登记。注意 4.2 的 TYPEPROP_DEBUG 构建仅用于 fixture 证据，不得混入正式 oracle 门禁（oracle 环境重建见 `/tmp/rugra-ghidra-bfd-2.38` 备忘）。

### 4.4 反向回归
W6 修正后补 volatile-read type-locked 单测：guard 输出不再被 STOP 封禁（special_prop 不参与 getLocalType 提前返回，可由 4.1 组 (d) 变体覆盖）。

---

## 5. 附：证据文件路径
- Oracle：`ghidra/.../cpp/varnode.cc:900-936`、`varnode.hh:118-139/267/333-334`、`op.hh:108-120/215-217`、`coreaction.cc:5008-5037/5074-5113/5374-5416`、`coreaction.hh:960-977`、`ruleaction.cc:6517/6715/6753/7098/7142`、`funcdata_block.cc:966-970`、`funcdata_varnode.cc:762`
- Rust：`src/varnode.rs:103-115/141/1421-1428`、`src/op.rs:67/597-602`、`src/coreaction.rs:3651-3840/3846-3922/4343-4442`、`src/ruleaction.rs:16391/16517/13629/13696/16479`、`src/funcdata.rs:8873-8875/14050`、`src/typeop.rs`（D1 派发）、`src/merge.rs:3386-3430`（key 版 local-type，可作参照）
- 现症：`result/curl_cur.c:1122/1126`（7 层 `->total`）
