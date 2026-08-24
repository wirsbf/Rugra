# R18 — Cross-Review: HERITAGE-GUARD-SUBPIECE-CONST-0001

- 复核对象: worktree `/home/wirs/.cache/rugra-wt-subpiece`，分支 `agent/heritage-subpiece-const`，HEAD `8d138b92cc9553892046b0a1aa5eebdaf160cbb3`（工作区 clean）。
- 模块: `src/heritage.rs`（机制 C 核心算法白名单 `src/heritage*.rs`）。
- Oracle: 本仓 `ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`（Ghidra_12.0.4_build，锁定 oracle）。
- 复核方法: 独立打开并逐行读 Ghidra 原文（heritage.cc / funcdata_op.cc / funcdata_varnode.cc / address.cc / translate.cc / space 相关），独立推导四类语义清单后再对照 Rugra；未采信实现 Agent 的 Evidence 块自述。禁 cargo / 禁改仓库，runner 未重跑——after 证据以 metadata 内 pin 的 sha256 等式 + 文件哈希绑定链核实。
- 结论: **Cross-Review: APPROVE**（非阻断建议见 §7）。

---

## 1. Ghidra 原文关键语义（本复核独立摘录）

### 1.1 `Heritage::guardOutputOverlapStack` heritage.cc:1322-1375（全文已读）

```
1325  int4 sizeFront = (int4)(retAddr.getOffset() - addr.getOffset());
1326  int4 sizeBack = size - retSize - sizeFront;
1327  PcodeOp *insertPoint = callOp;
1328  Varnode *vnCollect = callOp->getOut();
1329  if (vnCollect == (Varnode *)0)
1330    vnCollect = fd->newVarnodeOut(retSize,retAddr,callOp);
1331  if (sizeFront != 0) {
1336    int4 truncateAmount = addr.justifiedContain(size, addr, sizeFront, false);
1337    fd->opSetInput(subPiece,fd->newConstant(4,truncateAmount),1);
1338    fd->opSetInput(subPiece,newInput,0);
1339    PcodeOp *indOpFront = fd->newIndirectOp(callOp,addr,sizeFront,0);
1340    fd->opSetOutput(subPiece,indOpFront->getIn(0));
1341    fd->opInsertBefore(subPiece,callOp);
1344    int4 slotNew = retAddr.isBigEndian() ? 0 : 1;   // 前件 PIECE
1348    vnCollect = fd->newVarnodeOut(sizeFront+retSize,addr,concatFront);
1349    fd->opInsertAfter(concatFront, insertPoint);
1350    insertPoint = concatFront;
1352  if (sizeBack != 0) {
1355    Address addrBack = retAddr + retSize;
1358    int4 truncateAmount = addr.justifiedContain(size, addrBack, sizeBack, false);
1361    PcodeOp *indOpBack = fd->newIndirectOp(callOp,addrBack,sizeBack,0);
1362    fd->opSetOutput(subPiece,indOpBack->getIn(0));
1366    int4 slotNew = retAddr.isBigEndian() ? 1 : 0;   // 后件 PIECE
1370    vnCollect = fd->newVarnodeOut(size,addr,concatBack);
1371    fd->opInsertAfter(concatBack, insertPoint);
1373  vnCollect->setActiveHeritage();
1374  write.push_back(vnCollect);
```

### 1.2 `Address::justifiedContain` address.cc:131-141（全文已读）

- 卫语句 1 `op2.offset < offset → -1`；卫语句 2 `off2 > off1 → -1`（off1=容器末，off2=被含末）。
- 路由键 `base->isBigEndian() && !forceleft`：BE 返回 `off1-off2`（末端距离），否则 `op2.offset-offset`（起点距离）。`base` = 容器地址所在空间。

### 1.3 `Funcdata::opSetOutput` funcdata_op.cc:70-87（全文已读）

`vn==getOut() 早退 → opUnsetOutput(旧出) → vn->getDef() 非空则 opUnsetOutput(vn->getDef()) → vn=vbank.setDef(vn,op)（可返回 canonical 化对象）→ setVarnodeProperties(vn) → op->setOutput(vn)`。即完整 def 接线（written 状态 + vbank 登记），非裸字段写。

### 1.4 `Funcdata::newIndirectOp` funcdata_op.cc:683-697（全文已读）

`newVarnode(sz,addr)` 自由 varnode → in[0]；`newVarnodeOut(sz,addr,newop)` → out；in[1]=newVarnodeIop(indeffect)；**`opInsertBefore(newop,indeffect)`** — INDIRECT 先插到 call 前。

### 1.5 `Funcdata::opInsertBefore` funcdata_op.cc:345-366（全文已读，本复核的决定性发现）

非 INDIRECT 的 op 插在 `follow` 之前时，**先回跳过紧邻 follow 的连续 INDIRECT 组**，插到该组之前。`opInsertAfter` (:373-397) 对称：prev 为 INDIRECT marker 时跳到目标 op，非 MULTIEQUAL 插入时前跳过连续 MULTIEQUAL 组。

### 1.6 栈空间端序来源 translate.cc:57-65

`SpacebaseSpace` 构造把 **`t->isBigEndian()`**（处理器端序）传给 `AddrSpace`——Ghidra 中栈空间端序 = 处理器端序，cc:1336/cc:1358 的路由输入在 BE 架构下确实是 BE。

## 2. 五触点逐项对照

### 触点 1 — 前后件 SUBPIECE 常量（Rugra src/heritage.rs:3377-3385, 3432-3440）

- 调用形态 6 参 `justified_contain_range(base=addr, sz2=size, addr=op2, sz=sz2, force_left=false, space_is_big_endian=AddressSpace::Stack.is_big_endian())`，与 `addr.justifiedContain(size, op2, sz2, false)` 的 `(this,sz,op2,sz2)` 参数对应关系正确（Rust 参数名 `sz2`=容器尺寸、`sz`=被含尺寸，与 Ghidra 形参名互换——语义映射已逐参数核实，fspec.rs:4547-4571 守卫序与 address.cc:133-141 逐行镜像，BE 分支 `this_end-end_addr`、LE 分支 `addr-base`，u64 wrapping 与 Ghidra uintb 回绕一致，sz=0 的 `addr-1` quirk 两侧同形）。
- **前件手推**（op2==addr，sf≤size 卫语句恒过）：LE=`addr-addr`=0；BE=`(addr+size-1)-(addr+sf-1)`=size−sizeFront。✓ 公式与代码一致。
- **后件手推**（addrBack=ret+retsz，end=addr+size−1 恰等 off1）：LE=`(sf+rs)-0`=sizeFront+retSize（≠0，旧代码错抄前件 LE 值 0——缺陷确认）；BE=`size−sf−rs−sb`=0。✓
- 端序路由来源：Ghidra 用区间空间（stack）端序（§1.6）；Rugra 用 `AddressSpace::Stack.is_big_endian()`（space.rs:172，过渡期枚举硬编码 `false`）。LE 生产域（x86-64）等价；BE 全函数路由在 Rugra 模型内不可staging——已归 ADDRESS-0001 残差（§6）。fixture case2 的 LE 行走**生产同款表达式**（`AddressSpace::Stack.is_big_endian()`），非旁路。

### 触点 2 — insertPoint 游标（src/heritage.rs:3362, 3413-3414, 3464）

`insert_point` 初值 call → 前件 concat `op_insert_after(&concat,&insert_point)` 后推进 `insert_point=concat` → 后件 concat 插在游标后。镜像 cc:1327/1349-1350/1371。旧代码两处都插 call 后，配合 `op_insert_after` 的"紧后插入"语义会把后件 concat 挤到 [CALL, concatB, concatF]——前后并存时顺序颠倒，缺陷确认。
插入序完整链条（含 §1.4/1.5 的 INDIRECT 前插 + 回跳）geom0 手工推演（与 metadata expect 一致）：
`[indF,CALL]` → subF 回跳过 indF → `[subF,indF,CALL]` → indB 紧前插 → `[subF,indF,indB,CALL]` → subB 回跳过 indB、indF → `[subF,subB,indF,indB,CALL]` → concatF 插 CALL 后、concatB 插 concatF 后 → **`[subF,subB,indF,indB,CALL,concatF,concatB]`**（7 op）。Rugra `op_insert_before`（funcdata.rs:3390-3398）与 `op_insert_after`（:3720-3762，marker→targOp 跳转 + MULTIEQUAL 前跳）均逐行镜像回跳/前跳语义。

### 触点 3 — op_set_output 完整接线（src/heritage.rs:3397-3400, 3449-3452）

两处均 `ind_*.get_in(0)` 克隆后经 `fd.op_set_output(&sub_piece, vn)`。`op_set_output`（funcdata.rs:1811-1834）镜像 funcdata_op.cc:70-87：ptr_eq 早退 → op_unset_output 旧出 → 解除 vn 旧 def → `vbank.set_def`（取 canonical）→ `set_varnode_properties` → 写 output。旧裸写 `output` 字段绕过 setDef，SUBPIECE 输出与 INDIRECT in[0] 永远停留 free（F）——缺陷确认，且正是 before② 观察到的 F vs W。

### 触点 4 — cc:1329-1330 读输出死锁（src/heritage.rs:3355-3357）

旧单表达式 `call_op.read().unwrap().output...unwrap_or_else(|| fd.new_varnode_out(...))` 中 read guard 临时值存活到语句结束，闭包内 `new_varnode_out` 对同一 call op 取 write 锁 → 同线程读锁未释即写锁，std RwLock 死锁。call 无输出（pre_out=false 几何）必触发——"该路径此前从未被真实执行"成立。修复为 `let existing_out = ...;` 先落绑定再分支：guard 于分号处释放，Ghidra 语义（getOut 空则 newVarnodeOut(retSize,retAddr,callOp)）不变。锁序修复正确且无语义副作用；Ghidra 无锁，此为 Rust 侧基础设施纪律，不构成对齐偏离。

### 触点 5 — 尾部与 write 表（src/heritage.rs:3468-3469）

最终 `vn_collect.set_active_heritage(); write.push(vn_collect)` = cc:1373-1374，单次尾插。✓

（另核实未改动项的一致性：SUBPIECE slot0=newInput/slot1=const=cc:1337-1338 ✓；前件 PIECE newFront→1/vnCollect→0、后件 newBack→0/vnCollect→1 与 cc:1344/1366 的 **LE** 取值一致——BE slot 路由为硬编码，归 BE 残差域，见 §7 建议 2；`new_varnode_out((size_front+ret_size),addr,·)`/`(size,addr,·)` = cc:1348/1370 ✓；`saturating_sub` vs Ghidra 裸减在可达域（ret≥addr）等价。）

## 3. 四类决定性语义核对（独立清单 vs Rugra）

| 类 | Ghidra（独立摘录） | Rugra | 判定 |
|---|---|---|---|
| 引用/输出参数 | fd 全程突变（newOp/newVarnode/newConstant/newIndirectOp/opSetInput/opSetOutput/opInsertBefore/After/newVarnodeOut）；`write` 尾插 1 次（cc:1374）；addr/retAddr const 引用只读 | fd 经同名 helper 突变；`write: &mut Vec` push 1 次（:3469）；addr/ret_addr 按值只读 | ✓ |
| 循环边界/遍历序 | 函数体无循环；op 序=§2 触点 2 推演的 7-op 链；块内投影由 fixture 逐 op 钉住 | 同链（op_insert_before/after 镜像回跳/前跳） | ✓ |
| 计数器/累加器 | sf/sb 一次性预计算（cc:1325-1326），无计数器；守卫 `!=0` | :3346-3347 一次性预计算；守卫 `>0`。调用方 containment 保证 sf,sb≥0，可达域等价；负域归残差 | ✓（等价性有界，已登记） |
| 排序/比较键 | justifiedContain 卫语句序 + 端序路由键 `base->isBigEndian()&&!forceleft`（栈空间端序=处理器端序，§1.6）；PIECE slot 键 `retAddr.isBigEndian()` | 卫语句序/路由算术逐行镜像；路由输入 `AddressSpace::Stack.is_big_endian()`（过渡枚举恒 false=LE）；PIECE slot 硬编码 LE | ✓（LE 域等价；BE 域=UNTESTED 残差，§6） |

## 4. 双侧 fixture 47 行证据链核实

- 结构核算：envelope(1)+case 头(2)+geom 组 gs+op+write = 9/9/6/6/9（op 7/7/4/4/7 与 sf/sb 触发组合一一对应：geom0 f+b、geom1 f+b、geom2 b-only(sf=0)、geom3 f-only(sb=0)、geom4 f+b+cc:1329 预存输出分支）+ sp 行(5) = **47**，与 `expected_stdout_lines=47` 及 observation_schema 一致。
- 五几何参数：geom0(0x1000,16,0x1004,4)→sf4/sb8；geom1(0x2000,8,0x2002,4)→sf2/sb2；geom2(0x3000,8,0x3000,4)→sf0/sb4；geom3(0x4000,12,0x4002,10)→sf2/sb0；geom4(0x5000,16,0x5008,4,pre_out)→sf8/sb4。两侧 fixture（.cc SG 表 / .rs SG 表）逐值一致。
- **BE/LE 算术手工推演抽查（全部通过）**：
  - LE back（op 级，sb>0）= sf+rs：geom0=8、geom1=6、geom2=4、geom4=12 → 8/6/4/12 ✓
  - sp 行 LE back（5 行全算，geom3 sb=0 仍按 call-shape 计算）= 8/6/4/12/12 ✓（geom3: 2+10=12；sz2=0 的 `addr-1` quirk 两侧同形）
  - BE back = size−sf−rs−sb = 0（五几何全 0）✓
  - BE front = size−sf：16−4=12、8−2=6、8−0=8、12−2=10、16−8=8 → 12/6/8/10/8 ✓
  - LE front = 0（op2==addr）✓
- geom0 全量投影手工推演（op0=63 SUBPIECE in=[1000:10:F{ah},c4(0)] out=1000:4:W；op1=63 in=[1000:10:F{ah},c4(8)] out=1008:8:W；op2/3=61 INDIRECT in=[W,IOP] out=W；op4=7 CALL out=1004:4:W；op5=62 PIECE in=[1004:4:W,1000:4:W] out=1000:8:W；op6=62 in=[1008:8:W,1000:8:W] out=1000:10:W；write=1000:10:W{ah}）与 metadata expect（含 W 状态/ah/slot 布局/7-op 序）逐项自洽。
- 证据绑定链：worktree HEAD 的 `heritage_subpiece_const_1204.cc/.rs`、`src/heritage.rs`、`docs/api/heritage.md`、runner、`Cargo.toml`、`Cargo.lock` 七文件 sha256 与 metadata `comparand` 逐项相等（本次实测）；runner（625 行，pin-base schema2）自校验 oracle 四元身份（commit/tag/cpp tree/Makefile blob）+ 源树干净 + base commit/tree + 全部 comparand 哈希 + input_manifest 规范化 sha + coverage 表前缀断言（两 case 必须 MATCH、三项残差必须 UNTESTED）+ 输出 sha/diff/exit/行数/包络/case 序断言 + owned-files 运行前后不可变。after 结论 `ghidra_stdout_sha256 == rugra_stdout_sha256 = 3071fd7b…` 由 metadata 固化，且绑定的是本 commit 的 heritage.rs（overlay 单文件）。链条自洽。

## 5. before①/before② 变体合法性

- before①（预修复代码 geom0 超时无输出）：与触点 4 的死锁机理（pre_out=false → 闭包内写锁）严格自洽；geom0 为首个执行几何，挂死于 geom0 与"后续几何未达"一致。
- before②（仅解锁死锁、保留旧常量/插入/接线）：作为差异定位的中间态，**非提交物**——runner 与 commit 均不含该变体；其三类差异（back 常量 c4(0) vs oracle c4(8/6/4/12)、前后 concat 顺序颠倒、SUBPIECE out/INDIRECT in0 状态 F vs W）与三个代码修复一一对应，且 after 态（=HEAD）与 oracle 字节全等（单一 sha 等式），使中间态不可能污染结论。合法。
- 红线检查：before② 不是"先简化后对齐"——它从未进入版本历史；commit 的 Alignment Evidence 块含逐字签名摘录（heritage.cc:1322 与原文逐字符一致）与四类语义逐条核对，无机制 D 红旗信号。

## 6. UNTESTED 残差归属（三项，均合理）

1. `be_space_guard_staging`（→ADDRESS-0001）：过渡枚举 `AddressSpace` 无法staging BE 栈空间（space.rs:172 `is_big_endian()` 恒 false；而 Ghidra 栈端序=处理器端序，translate.cc:59），BE **全函数**路由（含 SUBPIECE 常量与 PIECE slot——二者同受 `retAddr.isBigEndian()`/`base->isBigEndian()` 路由）不可达；BE 算术已在 case2 sp be 行于 helper 级钉住（直接传 `true`，明示为 helper-level pinning 而非伪装全函数覆盖）。归属正确。
2. `production_entry_wiring`（→HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS）：guardCalls→tryOutputStackGuard 生产入口未驱动；Rugra `try_output_stack_guard` 对 cc:1407-1430 output-contains 分支保守返 false（向不欠保护方向：回落 unknown_effect INDIRECT）。fixture 直驱 guard 函数本体，入口接线不宣称覆盖。归属正确、方向安全。
3. `negative_piece_geometry`：sf<0/sb<0 由调用方 containment（getBiggestContainedOutput）排除，Ghidra `!=0` vs Rugra `>0` 可达域等价。归属正确。
- 总判定 `overall_status=UNTESTED` + `covered_projection_status=MATCH` 的双轨记录符合机制 B2（覆盖投影 MATCH 不得升函数级 MATCH），诚实。

## 7. 非阻断建议（单列）

1. **行号注脚 off-by-one（预存）**：src/heritage.rs:3328 `// Ghidra: heritage.cc:1323` 应为 **1322**（函数定义起始行；1323 是形参续行——机制 D cited-line-drift 卫生）；:3467 尾部注释 `cc:1374-1375` 实际 setActiveHeritage/push 在 cc:1373-1374（1375 是闭括号）；doc 注释 `heritage.cc:1323-1376` 宜改 1322-1375。均为注释层，不影响行为。
2. **BE 残差措辞**：ADDRESS-0001 残差应显式点名 **PIECE slot 硬编码**（src/heritage.rs:3407-3409、3458-3460 注释已自标 "LE:"）与 `space.rs:172` 的 `is_big_endian()==false`，防止未来 BE staging 只补 SUBPIECE 常量而漏 slot 路由（cc:1344/1366 的 `retAddr.isBigEndian()` 键）。
3. **投影残差**：varnode SPACE 字母因过渡期 `new_varnode_out` 寄存器空间 vs 区间空间分歧被投影掉（fixture 头部已声明且确属已登记分歧、不影响本 fixture 的观察面）；ADDRESS-0001 落地后应把空间字母加回投影重钉。
4. `justified_contain_range(base, sz2, addr, sz, …)` 形参命名（sz2=容器尺寸、sz=被含尺寸）与直觉相反，与 Ghidra 形参名互换；建议注释或改名降低误读风险（RUGRA-GLUE 层，行为已钉）。
5. `HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS` 目前只存在于主仓 TODO_BOARD 行 59 的派生引用与 metadata residuals，尚无独立行；root 集成时应实体化登记（铁律 3）。
6. 复核环境禁 cargo：commit 所称 "heritage 单测 12/12" 与 runner 重跑未由本复核独立复现；载重证据为 metadata 固化的 sha 等式 + 本次实测的文件哈希绑定（已核实绑定到 HEAD 8d138b92），风险可接受。

## 8. 判定

五触点全部与锁定 oracle 逐行对齐；四类决定性语义无 MISMATCH；47 行证据链结构、算术、绑定链自洽；before 变体合法且无害；三项 UNTESTED 残差归属正确且未伪装成 MATCH。

**Cross-Review: APPROVE**
