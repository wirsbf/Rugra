# R22 Cross-Review — HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS (commit 3dc4b2ae)

- Reviewer: 机制 C 独立复核 Agent（只读主仓；本文件为唯一写入物）
- 复核对象: `3dc4b2ae3c2b7a29104a26aa54c56d36380bdb70`（已集成 master，`git branch --contains` 确认）
- Oracle: ghidra/ HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`（= 锁定 12.0.4，独立 rev-parse 确认）
- 方法: 独立打开并通读 Ghidra `heritage.cc:1391-1431`、`address.cc:131-142`（justifiedContain 全函数）、
  `fspec.cc:4336-4356`（characterizeAsOutput locked 分支）、`coreaction.cc:1538-1553`（setStackOutputLock 前置）、
  `heritage.cc:1443-1527`（guardCalls 上下游）、`fspec.hh:1536`（getOutput 定义），不采信实现 Agent 的 Evidence 块。

## Cross-Review: APPROVE

## 1. 四类决定性语义核对（独立清单 vs src/heritage.rs:3508-3623）

### 1.1 引用/输出参数 — MATCH
- Ghidra `fc` 指针共享（getOp/cc:1394、getOutput/cc:1407+1410）→ Rugra `fd + fc_idx` 索引式共享，`find_call_op(fd)` 解析 call op，等价。
- `write: vector<Varnode*>&` 引用回传 → `write: &mut Vec<VarnodeRef>`，push 语义一致（仅 cc:1428 一处）。
- **locked_output_storage 暂存两次读取的等价性**：`fc->getOutput()` = `store->getOutput()`（fspec.hh:1536），cc:1407 与 cc:1410 两次读取之间无任何 mutation（两行之间只有 diff 计算与 Address 平移），返回同一 `ProtoParameter*`，恒等。Rugra 以 `Option<(Address, i32)>` 值快照暂存一次读取——值语义下等价（甚至更强：免疫中途突变）。Ghidra 侧该分支**不存在** return false 路径（cc:1406-1430 尾部恒 `return true`），Rugra 的 None→false 是声明的 FSPEC-OUTPUT-STORAGE-0001 残差（见 §4）。
- 返回 bool → guardCalls cc:1491-1492 将 unknown_effect 升级 unaffected；Rugra 同（heritage.rs:1466-1470）。

### 1.2 循环边界/遍历顺序 — MATCH
- 无循环。分支序逐行对齐：cc:1411 `outvn==0` 判空（rs:3572-3582）→ cc:1417 `size<retSize` **严格小于**（rs:3583，`if size < ret_size`，无 `<=`）→ cc:1426 `vnFinal!=0` 判空（rs:3617）。
- SUBPIECE 构造序完全一致：newOp(2, callOp->getAddr()) → opSetOpcode(SUBPIECE) → truncateAmount → opSetInput(const,1) → opSetInput(outvn,0) → newVarnodeOut(size,addr,subPiece) → **opInsertAfter(subPiece, callOp)**（cc:1418-1424 = rs:3586-3613）。in[0]/in[1] 槽位无颠倒。
- cc:1414 新建输出用 caller 视角 retAddr（rs:3578 `new_varnode_out(ret_size, ret_addr, &call_op)`，ret_addr 已含 diff 平移）。✓

### 1.3 计数器/累加器（vnFinal 单槽）— MATCH
- 初值 null（rs:3566 `None`）；outvn 为 null 时 `vnFinal = outvn`（rs:3579）；`size < retSize` 时**被覆盖**为 SUBPIECE 输出（rs:3611 赋值覆盖 Some，非 append）；仅非空时 `setActiveHeritage` + push **一次**（rs:3617-3620）。
- 关键 no-op 几何：outvn 已存在且 `size==retSize` → vnFinal 保持 null → 不 push、不 set 标志 → cc:1430 仍 `return true`。Rugra 同（fixture geom 6 双侧投影验证）。

### 1.4 排序/比较键（cc:1420 第四 justifiedContain 触点）— MATCH
- Ghidra: `retAddr.justifiedContain(retSize, addr, size, false)`，this=容器（caller 视角返回存储）、op2=contained（守卫区间）、forceleft=false。`address.cc:138` 以 `retAddr.base->isBigEndian()` 路由：BE → `off1-off2`（末端距离），否则 → `op2.offset-offset`（起始距离）。
- Rugra rs:3597-3604 `justified_contain_range(ret_addr, ret_size, addr, size, false, space.is_big_endian())`，helper（fspec.rs:4613-4637）逐行对齐 address.cc:133-141（含"两侧独立越界各自排除"的单边检查语义）。
- **端序路由键等价性**：`retAddr.space == addr.space == 传入 space`。依据：guardCalls cc:1457/1466 transAddr 与 addr 同 space；characterizeAsOutput（fspec.cc:4346/4351）内部的 justifiedContain `base != op2.base → -1` / containedBy 检查保证非 no_containment ⟹ 输出存储与 transAddr 同 space；cc:1409 的 `+diff` 平移不改 space；isStackOutputLock 前置（coreaction.cc:1546-1549）保证该 space 是 spacebase。故 `space.is_big_endian()` ≡ `retAddr.base->isBigEndian()`。
- helper 剥离的 `base != op2.base` 检查由可达性保证覆盖（不可达路径上 Ghidra 返回 -1 而 Rugra 不检查，但该路径已被 cc:1489 gate 排除）——注释已声明此约定（fspec.rs:4604-4608）。
- BE/LE 常量独立验算：容器 [0x1010,0x1018)，guard [0x1014,0x1018)：LE = 0x1014-0x1010 = 4，BE = 0x1017-0x1017 = 0；geom1/2/3 → LE 0/2/4、BE 4/2/0，与 commit/fixture 声明一致，且 BE 侧由 C++ fixture 直接调真 Ghidra `Address::justifiedContain` 于 `ram_be` 空间钉死（.cc:354-361）。

## 2. 死锁修复验证 — PASS
- 修复形态：rs:3572 `let existing_out = call_op.0.read().unwrap().output.as_ref().cloned();` —— read guard 是该 let 语句的临时值，语句结束即释放（`.cloned()` 产出 owned `Option<VnRef>`，不借用 guard）；随后 rs:3573 `match existing_out` 的 None 臂内 `fd.new_varnode_out(..., &call_op)`（rs:3578）对同一 op 取写锁时 read guard 已不在场。edition 2021 下 match scrutinee 临时值确活过臂体（drop-order 到 2024 才改），故内联 scrutinee 写法会自死锁——诊断正确，修复是必要的最小改动，与 guard_output_overlap_stack（cc:1329）的既有修复模式一致。
- 触达验证：双侧 fixture geoms 1-4（pre_out=false）正是该路径（Some 存储下 call op 无输出 → 新建），runner 以 `timeout 600` 驱动并通过 = 无挂起。函数体内其余 `call_op.0.read()`（rs:3586 get_addr）均为语句级 guard，不跨 `new_varnode_out`/`op_insert_after` 存活。
- 注意区分（易混点已核实无误）：`existing_out` 读的是 **op 的输出 varnode**（≡ Ghidra cc:1411 `callOp->getOut()`），而 `locked_output_storage` 暂存的是 **proto store 的返回存储**（≡ cc:1407/1410 `fc->getOutput()`）——两套读取未混淆。

## 3. 双侧 fixture 与 metadata 自洽 — PASS
- 六几何双侧逐项一致（.rs:99-106 ≡ .cc:263-268）：justified(0x1010,4/8)、+2(0x1012,4)、远端(0x1014,4)、size==retSize 无 SUBPIECE、pre_out 复用、pre_out+size==retSize 的 vnFinal-null no-op。分支覆盖矩阵：outvn 新建(1-4)/复用(5-6)、SUBPIECE(1-3,5)/无(4,6)、vnFinal 覆盖(1-3,5)/保留(4)/null(6)。
- staged outputCharacter 用 cc:4346 同一数学推导（.rs:141-146，0→CONTAINS_JUSTIFIED / >0→CONTAINS_UNJUSTIFIED），与 guardCalls cc:1489 gate 的 reachability 条件镜像；staging 差异（C++ 从真 ProtoParameter 读取 vs Rust 传 Some 元组）在 metadata `analysis_options.staging` 显式声明。
- metadata hash 自洽（独立 sha256sum）：worktree 与 3dc4b2ae blob 双重核对 — cpp_fixture `a44583a5…`、rust_fixture `09bc1bc0…`、runner `46f776e0…`、heritage.rs `94afe9d2…`（3dc4b2ae 时点 blob 相同，后续无改动）全部匹配 metadata comparand。oracle pin：commit/tag/cpp_tree `b02e230a`/Makefile blob `ca0719fa` 与 ghidra/ 实际 HEAD 一致。
- runner（837 行）：`--ghidra-only`/`--validate-only` 互斥模式、Ghidra stdout 锁定 hash 门禁（`b08f89a9…`，与 metadata `expected_stdout_sha256` 一致）、`env -i` 清洗 + GIT_CONFIG_NOSYSTEM、CARGO_NET_OFFLINE、amb cargo config 探测、timeout 600——门禁不可绕。
- coverage 8 行 = 6 MATCH + 2 UNTESTED（production_entry_wiring、be_stack_space），均绑定登记残差 ID（FSPEC-OUTPUT-STORAGE-0001 / 过渡 AddressSpace 枚举无 BE 栈空间），overall=PARTIAL_MATCH 的宣告诚实，未宣称 L3——符合机制 B2 状态表。

## 4. 生产入口 None 传递（FSPEC-OUTPUT-STORAGE-0001）保守方向 — PASS
- rs:1466-1468 生产 `guard_calls` 传 `None` → 函数在 rs:3553-3555 `let else` 立即 `return false` → guardCalls 侧 effecttype 停留在 cc:1490 的 `unknown_effect`。
- 下游（独立读 heritage.cc:1511-1520 确认）：`unknown_effect` → `newIndirectOp(callOp, addr, size, 0)` + in/out 双 `setActiveHeritage` + `write.push_back(out)`——即**创建** INDIRECT 数据流守卫。Ghidra 中 tryOutputStackGuard 返回 true 才升级 unaffected（跳过 INDIRECT）。
- 方向判定：None→false 少拿的是"unaffected 免守卫"的升级，多保的是 unknown_effect 的 INDIRECT——**over-protect**（多守卫），绝非 under-protect（不会把实际被调用写的 range 漏判 unaffected）。在 Rugra FuncProto 尚无 proto-store 输出存储（set_output_parameter 丢弃 pieces.addr）期间，这是唯一安全方向。Rust-only 回归测试 `test_try_output_stack_guard_none_storage_is_conservative_false`（heritage.rs:6599-6645）钉死：false + write 空 + op 无输出 + 块内单 op。

## 5. 非阻塞观察（记录，不构成 REJECT）
1. **`(int4)` 截断 / wrapOffset 差异**：Ghidra cc:1408 `(int4)(addr-transAddr)` 截断到 32 位、cc:1409 `Address::operator+` 走 `base->wrapOffset` 空间环绕；Rugra 用 u64 `wrapping_sub/add` 且不做空间环绕。仅当栈偏移逼近 2^31 或 space 环绕点时分歧——spacebase 栈窗口实际不可达，且同 helper 模式为 contained_by 分支（rs:3531-3532 ≡ cc:1400-1402）既有约定，非本次引入。
2. **find_call_op None → return false**：Ghidra `fc->getOp()` 恒非空（Funcdata 不变量），Rugra 的防御回退在不可达路径；同为保守方向（false → unknown_effect INDIRECT），可接受。
3. BE 栈空间不可 stage 是过渡 AddressSpace 枚举的已知限制（BE 路由由 C++ fixture 直调 oracle 钉死），残差已登记，非本次移植缺陷。

## 结论

四类决定性语义全部 MATCH；死锁修复正确且必要；fixture/metadata/runner/pin 三件套自洽且门禁真实；生产 None 残差方向保守安全且已登记。无 MISMATCH。

**Cross-Review: APPROVE**
