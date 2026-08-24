# R9 — HERITAGE-GUARD-NORMALIZE-0001 独立复核报告（机制 C）

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-heritage-guard`，分支 `agent/heritage-guard-normalize`
- 复核 commits：`d4705ae`（port）+ `8da9295`（fix）+ `54c6176`（fixture）
- 复核人：独立复核 Agent（R9）。**未采信实现者 Evidence 声明，全部 Ghidra 行为自行读源码重推。**
- Oracle 锁定核实：`/home/wirs/DEV/Rugra/ghidra` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b` = `Ghidra_12.0.4_build` ✓
- 复核方式：只读 worktree / 双侧源码 / git 产物；未执行 cargo、未改任何仓库文件。

---

## 结论

**APPROVE（有强制整改项，见 F1–F4；均不推翻已验证的核心移植语义，但必须在集成前后完成登记/文档修正）**

核心判定：六个移植函数在 LE 语料与 fixture 覆盖域内四类决定性语义逐项与 oracle 一致；双侧 fixture 真实、pin 自洽、状态保守（overall=MISMATCH，模块保持 L2）；case 2 registered mismatch 的归因经我独立数值重推**成立**，确为 fspec.rs 租约缺陷而非 heritage.rs 缺陷。未发现任何 Ghidra 没有的启发式（红旗自查通过）。发现 2 项技术性边界问题（BE overlap、property tail 欠应用）与 2 项流程违规（TODO/ROADMAP 未同步），已给出精确行号与修正方向，作为 APPROVE 的绑定条件。

---

## 1. 逐函数四类语义核对（我方独立读 Ghidra 原文后比对）

### 1.1 `Heritage::guard` ↔ `heritage.rs:2045 guard_range`（heritage.cc:1156-1199）

| 类别 | Ghidra 事实（我读到的） | Rugra | 判定 |
|---|---|---|---|
| 引用/输出参数 | read/write 由 collect 填充；`*iter = vn = normalizeWriteSize(...)`（cc:1180）回写 write 表项；fl 为 queryProperties 输出参数（database.cc:1270/1273/1279） | `*vn_arc = normalize_write_size(...)`（heritage.rs:2089-2090）回写；fl 为返回值，per-range 从 0 起算 | ✓ |
| 遍历顺序 | read 循环 cc:1164-1175（descend==0 continue、多读 throw、size<size 归一）；write 循环 cc:1177-1182；addIndirects 固定序 queryProperties→guardCalls→guardReturns→(highPtrPossible→guardStores,guardLoads) cc:1188-1197 | 全部镜像（2056-2114）；旧代码 `let fl: u32 = 0` + guardStores/Loads 无条件调用（diff 已删除），新代码加 highPtrPossible 门（cc:1194 ✓）且 guardReturns 接线在 guardCalls 之后 | ✓ |
| 计数器 | 无；fl per-range 局部，cc:1189 清零后查询 | guard_query_properties 每次从 0 计算 | ✓ |
| 排序/比较键 | halt 五位掩码 op.hh:171-172 | `HALT\|BADINSTRUCTION\|UNIMPLEMENTED\|NORETURN\|MISSING`（heritage.rs:1608-1614 等），op.rs:45-49 位值与 op.hh 一致 | ✓ |

残差（已登记）：cc:1171 多读 `throw LowlevelError` → Rust `eprintln!` + `lone_descend()` 为 None 时跳过归一（heritage.rs:2067-2078）。metadata `remaining_heritage_closure` 已列 "multi-descendant LowlevelError transport" UNTESTED ✓。

### 1.2 `Heritage::guardReturns` ↔ `heritage.rs:1674`（heritage.cc:1652-1692）——重点：halt 两个半边

- **activeoutput 半边（halt 排除）**：cc:1668-1669 `if (op->isDead()) continue; if (op->getHaltType() != 0) continue;`（"Special halt points cannot take return values"）。Rust 1712-1717：dead → continue；halt（五位掩码）→ continue ✓。
- **persist 半边（halt 包含）**：cc:1678-1691 循环体内**只有** `if (op->isDead()) continue;`（cc:1680），无 halt 检查 —— halt RETURN 也拿 return-copy。Rust 1735-1743：只查 dead ✓，注释明确"halt RETURNs included"✓。
- `(fl & Varnode::persist)==0 → return`（cc:1676）↔ heritage.rs:1730-1732 ✓。
- persist 半边序：newOp(1)（cc:1681）→ newVarnodeOut+setAddrForce+setActiveHeritage（cc:1682-1684）→ COPY（cc:1685）→ markReturnCopy（cc:1686 = `op->flags \|= PcodeOp::return_copy`，funcdata.hh:452；`return_copy = 0x80000`，op.hh:94；Rust `RETURN_COPY = 1<<19`，op.rs:43 ✓）→ newVarnode+setActiveHeritage（cc:1687-1688）→ opSetInput(.,0)（cc:1689）→ opInsertBefore（cc:1690）。Rust 1745-1776 逐步镜像 ✓。
- activeoutput 半分支序：contained_by → guardReturnsOverlapping（cc:1661-1662）；`!= no_containment`（即 contains_justified/unjustified）→ registerTrial + 全范围 input（cc:1663-1673）↔ Rust 1688-1727 ✓。Ghidra 未用的 `write` 参数省略，已注释（1673）✓。
- `fd->getActiveOutput()` = `activeoutput`（funcdata.hh:424）↔ `fd.active_output` ✓。

### 1.3 `Heritage::guardReturnsOverlapping` ↔ `heritage.rs:1573`（heritage.cc:1609-1638）

- `getBiggestContainedOutput` 失败 → return（cc:1615-1616）↔ 1580-1586 ✓。
- `registerTrial(truncAddr, vData.size)`（cc:1618-1619）↔ `register_trial_in_space(v_space, trunc_addr, v_size)`（1590-1592）。truncAddr 携带 vData.space ✓（Rugra Address 无 space，经参数显式携带，语义等价）。
- **BE/LE offset 重算（cc:1620-1622）**：`offset = vData.offset - addr.getOffset()`；BE 时 `offset = (size - vData.size) - offset` ↔ heritage.rs:1595-1599 逐字镜像（`(size as i64 - v_size as i64) - offset`）✓。
- 常量宽度 **4**（cc:1632 `newConstant(4, offset)`）↔ `new_constant(4, offset as u64)`（1637）✓。
- 创建序：invn=newVarnode（cc:1628）→ newOp（1629）→ SUBPIECE（1630）→ inputs（1631-1632）→ **opInsertBefore 在 newVarnodeOut 之前**（1633 → 1634）→ retVal=newVarnodeOut(vData.size, truncAddr)（1634）→ invn setActiveHeritage（1635）→ opInsertInput(op, retVal, numInput())（1636）。Rust 1628-1653 同序 ✓。num_input 在循环顶部捕获，循环体不改变该 op 的输入数，等价 ✓。
- RETURN 遍历：`beginOp(CPUI_RETURN)` 插入序 ↔ `fd.obank.returnlist`（op.rs:1622 在 op 插入时 push，创建序）✓。

### 1.4 `Heritage::normalizeWriteSize` ↔ `heritage.rs:1841`（heritage.cc:416-494）——LE 域

- 公式：`overlap = vn->overlap(addr,size)`、`mostsigsize = size-(overlap+vn->getSize())`（cc:426-427）↔ 1862-1864（LE 公式，见 F1 的 BE 限制）。
- **分支序** mostsigsize（cc:428-448）→ overlap（cc:449-469）→ midvn（cc:470-482）→ bigout（cc:483-492）↔ 1866-2016 ✓。
- **BE/LE pieceaddr**：mostsig 分支 BE=addr / LE=addr+(overlap+vn_size)（cc:429-433）↔ 1871-1875；overlap 分支 BE=addr+(size-overlap) / LE=addr（cc:451-454）↔ 1927-1931 ✓。
- CALL 分支：`op->isCall() && callOpIndirectEffect(pieceaddr, piecesize, op)` → `newIndirectCreation(op,pieceaddr,size,false)` 取 out（cc:434-437/455-457）↔ 1876-1894/1932-1944（`new_indirect_creation_in_space(..., false)`）✓。
- 非 CALL 分支创建序：newOp → newVarnodeOut(piece) → newVarnode(size,addr)+setActiveHeritage → SUBPIECE → slot0=big、slot1=常量（mostsig 分支常量 = `overlap+vn->getSize()`，cc:445；overlap 分支常量 = 0，cc:466）→ opInsertBefore(newop, op)。Rust 1899-1918 / 1948-1964 逐步镜像，常量宽度 = `space.addr_size()` ↔ `addr.getAddrSize()` ✓。
- midvn：BE 地址 = `vn->getAddr()`、LE = addr，大小 = overlap+vn_size（cc:472-475）；PIECE **slot0=vn（most significant）、slot1=leastvn**（cc:477-478）；`opInsertAfter(newop, op)`（cc:479）↔ 1969-1989 ✓。overlap==0 时 midvn=vn（cc:482）↔ 1991。
- bigout：PIECE slot0=mostvn、slot1=midvn，**锚点 `opInsertAfter(newop, midvn->getDef())`**（cc:489）↔ 1995-2012（mid_def 取 midvn.def；None 时回退 def_op —— overlap==0 时 midvn=vn，def=def_op，等价）✓。
- `vn->setWriteMask()`（cc:493）+ 返回 bigout（cc:494）↔ 2020-2022 ✓；guard 侧 `*iter = vn =` 回写（cc:1180）↔ 2089-2090 ✓。
- 旧实现（"common case only, falls back"文档化简化）被本 commit **替换为全量移植** —— 方向正确（diff 删除行核实）。

### 1.5 `Heritage::callOpIndirectEffect` ↔ `heritage.rs:3967`（heritage.cc:358-370）——极性修复

Ghidra 逐字：CALL/CALLIND → `fc = fd->getCallSpecs(op)`；`fc==null → return true`；`return fc->hasEffectTranslate(addr,size) != EffectRecord::unaffected`；其余（CALLOTHER/NEW）→ `return false`。Rust 3975-3988：非 CALL/CALLIND → false；无 spec → true；`has_effect_translate(...) != EffectType::Unaffected`。**极性与 cc:361-369 逐字一致**；注释明确记录旧 stub 恒 true 已废除 ✓。

### 1.6 `Scope::queryProperties` ↔ `heritage.rs:2138 guard_query_properties`（database.cc:1263-1281 + stackContainer cc:943-962 + mapScope cc:3185-3194）

- **三段序**：res(symbol) → finalscope(in-scope) → flagbase，与 database.cc:1268-1279 一致：entry → `getAllFlags()`；finalscope → `mapped|addrtied`（+global persist）`| getProperty(addr)`；否则 `getProperty(addr)` = flagbase.getValue（database.hh:946）↔ Rust 分支 (1) 2172-2191 / (2) 2197-2212 / (3) 2214-2220 ✓。
- guard 的调用形态：`fd->getScopeLocal()->queryProperties(addr,size,Address(),fl)` —— **空 usepoint**（cc:1191）↔ 静态投影无 usepoint ✓。空 usepoint 下 `SymbolEntry::inUse` 对非 addrtied 条目返回 false（database.cc:117-118），故 Ghidra 实际只可能命中 addrtied 符号；mapScope 无 namespace 解析时返回 qpoint=ScopeLocal（database.cc:3187-3188），Rust 直接从 ScopeLocal 起查，与该调用形态一致。
- **8da9295 space 修复**：`Scope::inScope` = `rangetree.inRange(addr,size)`（database.hh:597-598），RangeList 携带 space 身份 —— 只有 scope 自己的（stack）space 能命中 in-scope 分支。Rust `space == scope.space && local_range.any(first<=offset && last<=range_last)`（2197-2203）✓。修复前 register/ram 偏移数值落入 stack 窗口会错拿 `mapped|addrtied` —— 修复正确且必要。
- 残差（行内注释登记，2129-2134）：无父链（Ghidra stackContainer 会继续走上 global scope，`isGlobal→persist`）；Rugra 全局范围落到分支 (3) flagbase。case 3 的 persist 经 flagbase 分支传递（fixture 验证 persist1）✓。mapScope namespace 重定向未投影（未注释，见 F4）。
- 分支 (1) 精确性：见 F4（tie-break 与 use-limited 条目资格与 Ghidra findContainer 的 oldsize/inUse 规则有偏差，但该分支在 fixture 中无符号、metadata 标 UNTESTED）。

### 1.7 `Funcdata::newVarnode` 属性尾 ↔ `heritage.rs:2238 apply_new_varnode_flags`（funcdata_varnode.cc:148-165 / 104-127）

- Ghidra 尾部：`localmap->queryProperties(addr,size,Address(),vflags)`；entry!=null → `setSymbolProperties(entry)`；否则 `setFlags(vflags & ~Varnode::typelock)`（cc:162-166 / 114-119）。Rust：查询 + `set_flags(fl & !TYPELOCK)`（2243-2246）✓（entry 分支降级为同一查询的 flags 投影，注释登记）。
- **接线点核对（14 处，无过度应用）**：guardReturnsOverlapping invn(1631)/retVal(1649) ↔ cc:1628/1634；guardReturns invn(1723)/copy vn(1754)/copy invn(1772) ↔ cc:1670/1682/1687；normalizeWriteSize most_out+big(1908/1910) ↔ cc:440/441、least_out+big(1954/1956) ↔ cc:461/462、mid_out(1983) ↔ cc:473/475、big_out(2002) ↔ cc:485；rename 三处 input promotion(5075/5126/5202) ↔ renameRecurse cc:2498/2509 域。**未发现**对 Ghidra 用 newUnique/newConstant（无属性尾）的场合误用。
- 欠应用：见 F2。

### 1.8 辅助核对

- `ParamActive::registerTrial`（fspec.cc:1963-1976）：push ParamTrial(addr,sz,slotbase)；非 SPACEBASE → markKilledByCall；slotbase+=1 ↔ `register_trial_in_space`（fspec.rs:3467-3474）：`space != Stack → mark_killed_by_call()`，`slotbase += 1` ✓。
- `guardCalls` 的 `holdind = (fl&addrtied)!=0` → `indop->getOut()->setAddrForce()`（cc:1450/1516-1517）↔ heritage.rs:1343 + 1534-1536 ✓（case 6 行为验证 force1）。
- `Funcdata::newIndirectCreation`（funcdata_op.cc:710-728）：newConstant(sz,0) 输入、indirect_creation op/varnode 位、INDIRECT、Iop 第二输入、opInsertBefore ↔ funcdata.rs:3538-3577 结构一致（属性尾缺，见 F2）。

---

## 2. 双侧 fixture 验证

### 2.1 三件套 pin 自洽性（我在 HEAD 54c6176 实测）

- `heritage_guard_normalize_1204.cc`：git blob `3550acda…` = metadata `fixtures.git_blob_oid` ✓；sha256 `b2e889e3…` = metadata ✓。
- `heritage_guard_normalize_1204.rs`：git blob `df9ace37…` ✓；sha256 `46ac68b0…` ✓。
- runner sha256 `f2a7afc8…` = metadata `comparand.runner_sha256` ✓。
- `8da9295:src/heritage.rs` sha256 = `ab741f0f…` = metadata `heritage_rs_sha256` ✓；`git diff 8da9295..54c6176 -- src/heritage.rs` 为空（reviewed source == pinned source）✓。
- oracle 身份：metadata pin commit+cpp_tree+makefile_blob 与 runner 内嵌常量一致，且与 `/home/wirs/DEV/Rugra/ghidra` 实测 HEAD 相符 ✓。

### 2.2 runner 门禁完整性（tools/run_heritage_guard_normalize_oracle.sh 通读）

- oracle 四重身份（HEAD==commit、tag、cpp tree、Makefile blob）+ decompiler tree 干净检查；Rugra 三重 pin（commit+tree+src tree）+ critical source blob 校验；fixture hash + runner hash 校验；输入 manifest 与指纹从 pin **重推导**后比对（防手写 drift）；**强制保守状态**：`overall_status` 必须以 `MISMATCH:` 开头、5 个 covered 必须 MATCH、registered divergence 必须 MISMATCH、任何未登记 MISMATCH 即失败、residual 必须 UNTESTED。C++ 侧从锁定 commit 私有重建 libdecomp.a 后链接 fixture；Rust 侧独立 CARGO_TARGET_DIR + flock 串行。
- 受复核约束（禁 cargo）我未重跑双侧；判定基于 pin 自洽 + runner 逻辑 + 下述手推与源码级比对。双侧 stdout sha256（`61ec9041…`/`79be3c82…`）与 per-line divergence hash 为 metadata 登记值，runner 每次运行都会重验。

### 2.3 case 6（guard_retry_pass_boundary）边界手推（我独立推导，与 metadata coverage 记录一致）

- pass 0：register delay=0 已到、stack delay=1 未到 → stack 范围未 heritage，无 INDIRECT → `ind0=0` ✓。
- pass 1：stack [0x20,0x28) 新范围 → guard(addIndirects=true)。fl：无符号 → in-scope 分支：space==Stack ✓ 且 (0,511) 包含 [0x20,0x27] ✓ → `fl = mapped|addrtied`（无 arch → 无 flagbase 附加）。guardCalls：guardnorm_call 无 effect 记录 → unknown_effect；spacebase offset unknown → tryregister=false，output/input 均未激活 → `newIndirectOp` 创建 1 个 INDIRECT，`holdind`（fl 含 addrtied）→ out setAddrForce → `ind1=1`、force=1 ✓。guardReturns：active_output 为 None 跳过；fl 无 persist 跳过 ✓。highPtrPossible：无 arch → true（门内无 STORE/LOAD，无操作）。
- pass 2：范围已 guard（旧范围）→ addIndirects=false → 无新 INDIRECT → `ind2=1` ✓。
- `pass=3`（三次 opHeritage）、`heritagePass(stack,0x20)=1`（pass 1 首次登记）✓。与 coverage 行 "pass0 register-only (ind=0), pass1 stack guard fires once (ind=1) with fl=addrtied addrForce output, pass2 old-range inert (ind=1), heritagePass(stack)=1, pass counter 3" 完全一致。

### 2.4 case 1/3/4/5 投影与源码行为一致性抽查

- case 1（contains_justified 全范围 trial + halt 排除）：走 cc:1663-1673 分支，trial slot1、killedbycall=1（register 非 spacebase，fspec.cc:1973-1974 ↔ Rust `space != Stack`）✓。
- case 3（persist 后缀，halt 包含）：flagbase persist band [0x1000,0x2000] → 分支 (3) persist → 两个 RETURN（含 missing-halt）前各插 rc=1 COPY，out force1、persist 经 newVarnode 尾/rename promotion 传递 ✓。
- case 4（CALL piece）：write=R12:2 (call def)，range R10:4 → overlap=2、mostsigsize=0 → 仅 overlap 分支；callOpIndirectEffect(guardnorm_call 无记录 → unknown ≠ unaffected → true) → newIndirectCreation piece ic=1 @R10:2；midvn PIECE(vn,leastvn) out R10:4；bigout=midvn；原写 wmask=1；另加 guardCalls 整范围 unknown INDIRECT ✓ 与 coverage 一致。
- case 5（SUBPIECE piece）：w=R22:2 (INT_SUB def)，range R20:4 → overlap=2、mostsigsize=0 → overlap 分支非 CALL：SUBPIECE(big,0) @R20:2 + midvn PIECE(vn,leastvn)@R20:4；w_out wmask=1、read 首输入变为 PIECE 输出 ✓。

---

## 3. case 2 registered mismatch 归因独立核实（成立）

场景数值：查询范围 = register:0x0 size 8；模型输出 pentry = register:0x4 size 4（[0x4,0x8)）。

**Ghidra**：`ParamEntry::justifiedContain`（fspec.cc:248）非 join、alignment==0 → `Address::justifiedContain(4, R0, 8, forceleft?)`（address.cc:131-141）：`op2.offset(0x0) < offset(0x4)` → **-1**（只要任一侧越界即 -1；end 对齐与否无关）。off=-1 → 非 contains_justified/unjustified → `containedBy(R0,8)`（fspec.cc:199-207）：0x4≥0x0 且 0x7≤0x7 → true → **contained_by** → guardReturnsOverlapping（SUBPIECE 截断、trial @R4:4）。

**Rugra**：`justified_contain_range(base=0x4, sz2=4, addr=0x0, sz=8, force_left=false)`（fspec.rs:4455-4462）：`end_addr=0x7`、`this_end=0x7`；判据 1 `addr<base && end_addr<this_end` → `0x7<0x7` 为 false 不触发；判据 2 `addr>base` false → **不算越界**，落入计算 `(this_end-end_addr)=0` → 返回 0 → characterize 判 **CONTAINS_JUSTIFIED** → 整范围 trial @R0:8 + input promotion，guardReturnsOverlapping 不可达。

结论：差异确实源于 `justified_contain_range` 的 -1 极性（Ghidra "**任一侧**越界即 -1"，Rugra 仅在"单侧外凸且另一侧严格在内"两类组合下返回 -1；**低侧外凸+末端对齐**、**高侧外凸+起点对齐**、**双侧外凸（严格包含）**三种情况 Rust 均误判为 contained；高侧外凸+起点对齐场景还会触发 `(this_end-end_addr)` 的 u64 下溢）。与 heritage.rs 移植质量无关，heritage.rs:1573 guard_returns_overlapping 本身四类语义完整（见 1.3）。metadata 将其登记为 `FSPEC-JUSTIFIED-CONTAIN`（fspec.rs 租约）并双侧 pin，归因**成立**；但该 ID 尚未登记进 TODO 账本（见 F3）。

---

## 4. 红旗自查（机制 D）

- **无新增 Ghidra 不存在的启发式**：diff 删除行核实 —— 旧 `fl=0` 硬编码、旧"common case only"normalizeWriteSize 简化、旧无条件 guardStores/Loads 均被**替换**为 oracle 行为（门控/全量/查询），方向正确。
- **ANN-F**：全 diff 仅 docs/api/heritage.md 一行注记"ANN-F 默认模型输出 seed（coreaction.rs）不在本租约内，待 PARAM-BIND"——是**越界声明**而非移除任何代偿机制；本 slice 未删除任何 Ghidra 存在的机制。
- `fd.get_arch().map(...).unwrap_or(true)`（heritage.rs:2107-2110）：arch-less synthetic Funcdata 的测试胶水，行内注释声明"oracle 恒解引用 Architecture"，可接受。
- commit message Evidence 两处行号引用精度不足（cc:426 的 endian-aware overlap、database.cc:97 处的 findContainer oldsize 规则），见 F1/F4 —— 属"引用行号但语义细节未引用"红旗，修正方向已给出；不影响已验证行为。

---

## 5. 发现与整改项

### F1【中】normalizeWriteSize/normalizeReadSize 的 overlap 为 LE-only 投影，Evidence 声明过强
- 位置：worktree `src/heritage.rs:1862`（`vn_loc.saturating_sub(addr.as_u64())`）、`src/heritage.rs:1800`。
- Oracle：`Varnode::overlap(const Address&,int4)`（varnode.cc:217-228）**endian-aware**：LE = `loc.overlap(0,…)`；BE = `loc.overlap(size-1,…) ? op2size-1-over : -1`（即 BE 的 overlap 从最低显著侧起算 = `(addr+size)-(vn_off+vn_size)`）。BE 下 overlap 值不同 ⇒ 分支触发条件（overlap!=0 / mostsigsize!=0）互换、overlap-piece 的 pieceaddr（cc:452 `addr+(size-overlap)`）与 SUBPIECE 常量全部漂移 —— 不仅是 metadata 所写的 "BE-space pieceaddr selection"。
- 缓解：项目级 LE 边界已存在（src/varnode.rs:1487 `overlap_addr` 自声明 little-endian-only，VARNODE-INIT-0001 残差）；fixture metadata 已列 BE 为 UNTESTED；无任何 MATCH 声明覆盖 BE。
- 整改：(a) 复用/扩展 `Varnode::overlap_addr`（补 BE 分支与 -1 非包含哨兵）替代内联 `saturating_sub`；(b) 在 d4705ae Evidence 域外补一条文档 commit 修正"逐字镜像 cc:426-427"的表述为"LE 投影"；(c) 将 BE 限制从 fixture metadata 提升登记到 TODO/ROADMAP（"BE-space normalizeWriteSize/ReadSize 分支与常量整体 UNTESTED"，不只是 pieceaddr）。

### F2【中】newVarnode 属性尾欠应用（相对 8da9295 自己的声明 "guard family's bank-created varnodes"）
- Ghidra 经 newVarnode/newVarnodeOut 施加属性尾、Rugra 裸 bank 创建（缺 mapped|addrtied/persist-range flags）的 guard 家族位点：
  - `src/heritage.rs:1503`（guardCalls input-trial vn）↔ heritage.cc:1502 `fd->newVarnode(size,addr)`；
  - `src/heritage.rs:1797`（normalizeReadSize vn1）↔ heritage.cc:391；
  - `src/funcdata.rs:3354/3361`（newIndirectOp newin/newout）↔ funcdata_op.cc:689/692；
  - `src/funcdata.rs:3556`（newIndirectCreation newout）↔ funcdata_op.cc:719。
- 影响示例（今天主管线可达）：persist band 上 CALL 的 unknown-effect guard，Ghidra 的 INDIRECT in/out 带 persist，Rugra 不带；stack 窗口内 guardCalls INDIRECT varnode Ghidra 带 mapped|addrtied，Rugra 不带。当前 fixture 投影不含 mapped/addrtied 位、persist band 不与这些位点交叠，故未观测（covered MATCH 不受影响）。
- 整改：heritage.rs 两处可在本租约内直接补 `apply_new_varnode_flags`；funcdata.rs 两处需另立/并入 funcdata 租约 TODO（在 `new_indirect_op`/`new_indirect_creation_in_space` 内部施加尾段，或由调用方施加并在签名注释声明）；全部登记 TODO ID 后本条闭合。在这之前，8da9295 commit message 中 "persist-property ranges propagate exactly as the oracle does" 的表述应以 docs commit 限定为"已接线位点"。

### F3【流程，铁律 3】TODO_BOARD / ALIGNMENT_ROADMAP 未随三 commit 同步
- `docs/TODO_BOARD.md:77`：`HERITAGE-GUARD-NORMALIZE-0001` 仍为 `BLOCKED / unassigned`，fixture 文件名写错（`heritage_normalize_guard_1204.*` / `run_heritage_normalize_guard_oracle.sh`，实际为 `heritage_guard_normalize_1204.*` / `run_heritage_guard_normalize_oracle.sh`），无 evidence commit、无 owner、无剩余差异绑定。
- `FSPEC-JUSTIFIED-CONTAIN` 仅存在于 fixture metadata 内，**TODO 账本中不存在该 ID** —— 违反"每个剩余差异必须绑定 TODO ID"。
- `ALIGNMENT_ROADMAP.md:95`（行 12 heritage.cc）：仍描述本 slice 已修复的缺陷（"callOpIndirectEffect 对 CALLOTHER/NEW 极性错误；normalizeWriteSize 不返回并回写；guard 写死 flags 且漏 guardReturns"）为现存状态 —— 模块状态描述已过时（L2 定级本身不变，仍 MISMATCH）。
- 整改：一个 docs commit 完成三处同步（TODO 行更新状态/owner/evidence=`d4705ae`+`8da9295`+`54c6176`/验收=runner/剩余差异绑定 FSPEC-JUSTIFIED-CONTAIN + F1/F2 新 TODO；ROADMAP 行 12 描述刷新；修正 fixture 文件名）。

### F4【低】guard_query_properties 分支 (1) 的两个精度残差（当前 fixture 无符号、UNTESTED 域）
- tie-break：Ghidra `ScopeInternal::findContainer`（database.cc:2265-2279）以**最小 entry 尺寸**胜出（oldsize 比较，从最大 subsort 反向遍历，同尺寸先见者胜）；Rust（heritage.rs:2154-2171）以**最小 subsort** 胜出、同 (0,0) 时取 symbols 插入序首个 —— 多个嵌套包含符号并存时选择不同。
- use-limited 条目资格：空 usepoint 下 Ghidra `SymbolEntry::inUse` 对非 addrtied 条目返回 false（database.cc:117-118）故不可选；Rust 分支 (1) 可选中 `usepoint==Some` 的符号并返回其 flags（Ghidra 会落入 in-scope/flagbase）。
- mapScope 的 namespace 重定向（database.cc:3185-3194）未投影亦未注释（父链残差已注释）。
- 整改：并入 `guard_fl_scope_symbol_flags`（varmap 符号租约）TODO 的验收项：分支 (1) 需 (i) 过滤 use-limited 条目、(ii) tie-break 改为 min-size（Ghidra oldsize 规则）、(iii) 补注释 mapScope 残差；在该租约交付前该分支保持 UNTESTED。

---

## 6. 判定矩阵（机制 B2 状态，我方核定）

| 函数 | 状态 | 依据 |
|---|---|---|
| guard_range（guard） | LE/MATCH（fixture case 1/3/4/5/6 闭包）；BE overlap 域 UNTESTED | 1.1 / F1 |
| guard_returns | MATCH（case 1/3；halt 双半边独立验证） | 1.2 |
| guard_returns_overlapping | 实现完整；经 fixture 的可达性被 fspec 极性缺陷阻断 → MISMATCH（登记，归因核实成立） | 1.3 / 第 3 节 |
| normalize_write_size | LE/MATCH（case 4/5 两分支）；BE 域 UNTESTED（F1，范围大于 metadata 表述） | 1.4 |
| call_op_indirect_effect | MATCH（极性逐字 + case 4 CALL 分支） | 1.5 |
| guard_query_properties | 空 usepoint/无符号/in-scope/flagbase 三段 MATCH（case 1/2/3/6）；符号分支 UNTESTED（F4） | 1.6 |
| apply_new_varnode_flags | 14 接线点语义一致、无过度应用；4 个 guard 家族位点欠应用 → UNTESTED 残差（F2） | 1.7 |

模块状态：**保持 🔧 L2 / overall MISMATCH**（与 metadata 一致；不满足升 L3 条件）。`covered_projection_status=MATCH` 与 overall MISMATCH 并存是 fixture 语义（covered 域内 5/6），可接受，但建议在 TODO 行写明以免误读。

## 7. 复核可重复性

- Oracle 源：`/home/wirs/DEV/Rugra/ghidra/.../cpp/{heritage.cc, database.cc, database.hh, funcdata_op.cc, funcdata_varnode.cc, fspec.cc, fspec.hh, op.hh, varnode.cc, address.cc, funcdata.hh}` @ `e40ed130`。
- Rugra 源：worktree HEAD `54c6176`（src/heritage.rs 与 pin `8da9295` 逐字节一致，sha256 `ab741f0f…` 已核）。
- 复跑入口：`tools/run_heritage_guard_normalize_oracle.sh`（本复核因约束未执行；其内部对双侧 stdout hash、保守状态、未登记 MISMATCH 均有硬门禁）。
