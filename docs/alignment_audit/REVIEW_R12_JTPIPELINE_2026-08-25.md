# R12 — JUMPTABLE-PIPELINE-0001 段1 独立复核（机制 C）

- 复核对象: worktree `/home/wirs/.cache/rugra-wt-jtpipeline-s1`，分支 `agent/jtpipeline-s1`，HEAD `88ede48`
- 复核人: R12（独立复核 Agent，只读 worktree/git/双侧产物，未改任何仓库文件，未跑 cargo）
- 方法: 自行打开锁定 oracle（Ghidra 12.0.4, commit `e40ed13014025f82488b1f8f7bca566894ac376b`）逐行阅读任务指定段落，独立列四类语义清单后与 Rugra 代码逐项比对；不采信实现者 Evidence 声明。
- 复核日期: 2026-08-25

## 0. 判定

**APPROVE**（含 **rangeutil.rs 伴随修复追认/ENDORSE**，见 §2）。非阻断建议 7 条见 §7。
本 APPROVE 覆盖段1 范围（模型链/find_normalized/EmulateFunction 错误通道）；`pipeline_env_note` 残留按 fixture 登记仍为 MISMATCH，段2/段3 完成前不得宣称模块 L3——与 metadata `projection_status=MISMATCH` 一致，诚实。

## 1. 必读 Ghidra 段落独立阅读确认（oracle = 12.0.4 e40ed13）

| 段落 | 独立阅读确认的关键语义 |
|---|---|
| jumptable.cc:2253-2285 `JumpTable::recoverModel` | 链序 override(matchsize=0, 忽略返回值直接 return) → 删除旧 jmodel → `indirect->getIn(0)` isWritten 且 def 为 CALLOTHER 时 JumpAssisted → JumpBasic → JumpBasic2(`initializeStart(jbasic->getPathMeld())` 拷走 pathMeld 后 `delete jbasic`, cc:2279-2281) → `delete jmodel; jmodel=0`。**链中无 Trivial**。 |
| jumptable.cc:1418-1431 `JumpBasic::recoverModel` | `jrange=new JumpValuesRange` → `findDeterminingVarnodes(indop,0)` → `findNormalized(fd,indop->getParent(),-1,matchsize,maxtablesize)`（pathout=-1）→ `getSize()>maxtablesize` 拒绝 → `markFoldableGuards`。 |
| jumptable.cc:1204-1234 `findNormalized` | analyzeGuards → findSmallestNormal → `sz>maxtablesize && numCommonVarnode==1 && vn->isReadOnly()` 时 `MemoryImage mem(vn->getSpace(),4,16,glb->loader); val=mem.getValue(offset,size)`，然后 varnodeIndex=0 / `setRange(CircleRange(val,size))` / setStartVn / setStartOp(getOp(0))。 |
| jumptable.cc:554-591 `findDeterminingVarnodes` | DFS slot-first 前进、耗尽弹栈；`pathMeld.empty()` 兜底 `pathMeld.set(op,op->getIn(slot))`（不 throw）→ meld 恒非空。 |
| jumptable.cc:1165-1191 `findSmallestNormal` | varnodeIndex=0 起步；循环内 `maxsize==matchsize` 提前 return（cc:1180）；`sz<maxsize` 才收紧；256 特例为**两条件** `(sz!=256)||(vn->getSize()!=1)`（cc:1185），采纳时 setRange/setStartVn/setStartOp(getEarliestOp(i))。 |
| jumptable.cc:2095-2110 `JumpAssisted::recoverModel` 前置形状 | addrVn isWritten → def 非 null → CALLOTHER → `numInput>=3` → userop 类型==jumpassist → switchvn=getIn(1) → 其余输入全常量；之后 cc:2111-2122 读 JumpAssistOp 载荷（calcSize 脚本或首参 sizeIndices）。 |
| jumptable.cc:1574-1611 `JumpBasic::sanityCheck` | 空表 true；首址非 0 时逐项：遇 0 地址 break；`|diff|>0xffff` 时 `loadFill(buffer,4,addr)` try/catch DataUnavailError，`!dataavail` 才 break（cc:1588-1598）；循环走完 i==size；`i==0`→false；`i!=size`→resize(i)+`jrange->truncate(i)`+`loadpoints.resize(loadcounts[i-1])`。 |
| jumptable.cc:216-254 `EmulateFunction::emulatePath` | 找 startop 索引 i（未找到 i==numOps）；startop 是 MULTIEQUAL 时找 `getIn(j)==startvn`，`(j==numInput)||(i==0)` throw "Cannot start jumptable emulation with unresolved MULTIEQUAL"；否则 startvn=out、i-=1；`i==numOps` throw "Bad jumptable emulation"；非 constant startvn 写值；`while(i>0){curop=getOp(i);--i;...}` **op0 不执行**；DataUnavailError 就地转 "Could not emulate address calculation at <addr>"，其余 LowlevelError 穿透；返回 `getVarnodeValue(getOp(0)->getIn(0))`。 |
| jumptable.cc:129/135 | "Branch encountered emulating jumptable calculation" / "Indirect branch encountered emulating jumptable calculation" 原文。 |
| jumptable.cc:1434-1460 `buildAddresses` | clear → EmulateFunction → funcptr_align mask → `initializeForReading`/`getValue`/`emulatePath`/`addressToByte`/mask → push → `loadcounts->push_back(loadpoints->size())`（cc:1456-1457，累计值）→ next。 |
| emulateutil.cc:47-58 `getLoadImageValue` | `loadFill(&res,sizeof(uintb)=8,addr)`；host/空间端序 swap；大端且 sz<8 右移，否则 `res &= calc_mask(sz)`。 |
| emulateutil.cc:97-108 `executeMultiequal` | `bl=currentOp->getParent(); last_bl=lastOp->getParent();` 按 in 边身份找 last_bl；`i==sizeIn()` throw "Could not execute MULTIEQUAL"；值取 `getIn(i)` 写 out。 |
| emulate.cc:143-211 `executeCurrentOp` | special dispatch: LOAD/STORE/CBRANCH(条件)/BRANCH/BRANCHIND/CALL/CALLIND/CALLOTHER/RETURN→executeBranchind/MULTIEQUAL/INDIRECT/SEGMENTOP/CPOOLREF/NEW + unary/binary + fallthruOp。 |
| rangeutil.cc:256-273 `CircleRange::getSize` | `left<right → (right-left)/step`；否则 `(mask-(left-right)+step)/step`（uintb 回绕），`val==0` 溢出分支 "We lie by one"：`val=mask; step>1 时 val=val/step+1`。 |
| rangeutil.hh:82 `CircleRange::getNext`（inline） | `val=(val+step)&mask; return val!=right;` — C++ uintb 无符号回绕加法。**注意：getNext 定义在 rangeutil.hh:82，rangeutil.cc 中无此函数。** |
| funcdata_block.cc:491-548 `stageJumpTable` | 双 catch：`JumptableThunkError→fail_thunk`；`LowlevelError→warning(err.explain,addr)+fail_normal`。 |
| architecture.cc:1433 | `max_jumptable_size = 1024` 默认。 |
| jumptable.cc:2623-2648 `recoverAddresses` | `jmodel==0` throw "Could not recover jumptable at … Too many branches"；`getTableSize()==0` throw "Jumptable with 0 entries at …"；collectloads 分支带 loadcounts + collapseTable。 |
| jumptable.cc:1962-1976 `JumpBasicOverride::recoverModel` | 两条路径均 `return true`（恒成功）。 |

## 2. 清单 2（重点）— rangeutil.rs 伴随修复：**追认（ENDORSE）**

租约外判定：TODO_BOARD 段1 write-set 仅 `src/jumptable.rs`；实现者在 commit message 自标 "outside the strict jumptable.rs lease, flagged for root"，runner 将 rangeutil.rs 以 overlay 形式注入快照并在 metadata comparand 单列 `rangeutil_overlay_sha256`。处置规范，符合并行协作纪律。

### 2.1 必要性（确为对齐 rangeutil.cc/hh 的必要修复）
- **`get_size`（cc:256-273）**：旧实现 step==1 时 `left==right → return mask+1`（mask=u64::MAX 时 debug panic / release 回绕为 0，语义全错）；回绕 range（left>right）时 `right.wrapping_sub(left) & mask` 与 Ghidra 公式数学不等价——反例 left=0xF0,right=0x10,mask=0xFF,step=1：Ghidra `(0xFF-0xE0+1)/1=32`（正确），旧 Rust 得 `0x80=128`（错误）。新实现逐字移植 else 分支与 lie-by-one 分支（含 step>1 的 `mask/step+1`），wrapping_sub/wrapping_add 对应 C++ uintb 回绕。逐行比对无偏差。
- **8 字节满幅拒绝路径依赖**：`findNormalized` 的 `sz>jrange->getSize()>maxtablesize` 拒绝（cc:1212-1213 与 cc:1428-1429）在 8 字节满幅 domain 时恰好走 lie 分支（(mask+step)/step 回绕 0 → 返回 mask=0xFFFF… → sz>1024 → 拒绝）。旧代码此点或 panic 或得 0 导致不拒绝。修复确为段1 观察面（模型链选择）所依赖。
- **`next`（rangeutil.hh:82）**：`val=(val+step)&mask` 在满幅 + 大 val 时溢出 u64；旧 `*val + self.step` debug panic。改 wrapping_add 必要且正确。

### 2.2 最小化（无夹带）
diff 仅触及 `CircleRange::next` 与 `CircleRange::get_size` 两个函数（36 行含注释），无其它行为改动。✓

### 2.3 瑕疵（非阻断，建议 A）
注释 `// Ghidra: rangeutil.cc:179 CircleRange::next`（预存）与新增 `// Ghidra rangeutil.cc:181: …` 属**行号漂移**：`getNext` 实为 rangeutil.hh:82 的 inline 定义；rangeutil.cc:179/181 位于 `(lft,rgt,size,stp)` 构造器体内。`tools/check_ghidra_refs.py` 只验行号存在故能通过，但按机制 D cited-line-drift 应修正为 `rangeutil.hh:82`。docs/api/rangeutil.md 新增文案沿用 cc:181，同源错误。Evidence 块引用的 `rangeutil.cc:256 CircleRange::getSize` 本身正确。

## 3. 清单 1 — 四类语义逐项独立验证（src/jumptable.rs）

### 3.1 模型链优先级序（recover_model @4417）✓
override → (in0 written + def CALLOTHER) JumpAssisted → JumpBasic → JumpBasic2(initialize_start 后) → None，逐分支与 cc:2253-2285 同序；override 分支 matchsize=0 ✓；Assisted 判定形态（isWritten→def→CALLOTHER）与 cc:2264-2268 一致，形状细节正确下沉到 `JumpAssisted::recover_model`（Ghidra 结构相同）。每级失败继续下一级、全失败 `jmodel=None` ✓。
- Ghidra override 分支忽略返回值直接 return；Rugra `return m.recover_model(...)` 传播 Ok(bool)。**不可观测**：`JumpBasicOverride::recoverModel` 两侧均恒返回 true（cc:1962-1976 两条路径 return true；Rugra 3762 同）。

### 3.2 原地换装 jmodel ✓
Rust 无 delete，以字段替换表达 cc:2262/2268/2274/2278 的 delete+new；Basic2 前先 `initialize_start(jbasic.get_path_meld())`（origPathMeld 拷贝，cc:1651-1660 对齐：empty→extravn=None；否则取 `numCommonVarnode()-1` + `set_from`）再丢弃 jbasic，与 cc:2279-2281 的拷走-后-delete 等价。

### 3.3 emulatePath op 递减边界（op0 不执行）✓
`while cur_i>0 { curop=get_op(cur_i); cur_i-=1; … }` 与 cc:239-251 同构：执行 op[i]…op[1]，op[0]=BRANCHIND 不执行；返回 `get_op(0).get_in(0)` 的值 ✓。

### 3.4 MULTIEQUAL start `j<numInput && i!=0` ✓
Rugra：`found_j == num_input || i == 0 → Err(Lowlevel "Cannot start jumptable emulation with unresolved MULTIEQUAL")`（消息逐字）；否则 startvn=out、`cur_i = i-1` ✓（cc:222-234）。`i==num_ops → "Bad jumptable emulation"` 检查的是原始 i ✓。执行期 MULTIEQUAL 入边解析 `Arc::ptr_eq(e.point, last_bl)` 对应 `bl->getIn(i)==last_bl` 指针身份比较，找不到抛 "Could not execute MULTIEQUAL"（emulateutil.cc:105 逐字）✓。

### 3.5 maxtablesize ✓
`recover_addresses_classified` 从 `Architecture::max_jumptable_size` 读取、缺 Architecture 回退 `MAX_JUMPTABLE_SIZE=1024`（architecture.cc:1433 默认一致）✓。findSmallestNormal 的 maxsize 单调收紧（仅 `sz<maxsize` 更新）+ `maxsize==matchsize` 提前返回（break，循环后无代码，与 return 等价）✓。

### 3.6 findSmallestNormal 尺寸最小 + 256 特例 — Ghidra 侧一致，Rugra 有**预存**第三条件
Ghidra cc:1185 为两条件 `(sz!=256)||(getSize()!=1)`；Rugra @2489-2491 为三条件 `sz!=256 || size!=1 || path_meld.is_load_in_path(i)`。grep 证实 Ghidra 全库无 isLoadInPath；该条件由旧 commit `ea7e10d` 引入，**本次 diff 未触碰**，且已登记于 TODO_BOARD `JUMPTABLE-HYGIENE-0001`（"is_load_in_path 漂移"）。行为差异（sz==256 ∧ size==1 ∧ load-in-path 时 Rugra 采纳、Ghidra 不采纳）属预存债务，不构成本次 MISMATCH；建议 B 补充登记可观测差异描述。
另：Rugra `num_common_varnode()==0 → return` 防御 guard 为 Ghidra 无有的保守分支（Ghidra 由 findDeterminingVarnodes 的 `pathMeld.set(op,in)` 兜底保证非空，cc:586-590；Rugra 兜底同款存在 @2374-2382），不可观测。

## 4. 清单 3 — Trivial 回退删除正当性 ✓
- grep jumptable.cc/.hh 全文：`JumpModelTrivial` 的构造仅 cc:2728，位于 `JumpTable::recoverLabels` 的 `jmodel==0` 分支（cc:2710-2731），**不在 recoverModel 链**（cc:2253-2285 无 Trivial）。
- 旧 Rugra（88ede48^）链尾的 `JumpModelTrivial` 回退系自创（旧代码注释自认 "mirror the sequence with the available models"）；本次删除正确。
- `JumpModelTrivial` 类型本身保留（src/jumptable.rs:1681），recoverLabels 未来对齐时仍可用——无误删。

## 5. 清单 4 — fail-closed 契约等价性 ✓（论证成立）
- **indop.parent 缺失 → Ok(false)**（recover_model @2804）：Ghidra `indop->getParent()` 为 null 时把 null 传入 findNormalized→analyzeGuards 即解引用崩溃——该状态在 Ghidra 正常流程（BRANCHIND 恒挂在块内，stageJumpTable 先验可达性）不可达。Rugra 以 Ok(false) 终止本模型并沿链降级，最终以 `jmodel==None → LowlevelError("Could not recover jumptable at … Too many branches")` 报告（与 recoverAddresses cc:2627-2631 同消息）。"不可达路径上 Ghidra 崩溃=从不产生输出，Rugra fail-closed 不产生错误成功" 成立，且方向安全（不会把坏表报成功）。
- **executeMultieQUAL lastOp 为 null → Lowlevel 同消息**（@5018）：Ghidra cc:104 `lastOp->getParent()` 空指针崩溃同样仅在"第一个执行 op 即 MULTIEQUAL 且无 lastOp"的不可达状态触发；Rugra 显式 Err 更严格，等价性论证同上。
- fixture `pipeline_env_note` 行明示 `raw_fd_recover=fail_closed_parent_contract`，残留如实绑定 JUMPTABLE-PIPELINE-0001。

## 6. 清单 5 — 双侧 fixture 8/8 与 pins 自洽 ✓
- **观察面实测**（存档 `/home/wirs/.cache/a22-jtp-tmp/dev-s1/{o,r}.txt`）：双侧 8 行逐字节一致，sha256 `4de63f58…` 与 metadata `expected_results.ghidra/rugra_stdout_sha256` 一致；`raw_diff_sha256`/双侧 `stderr_sha256` 均为空文件 sha `e3b0c442…`；exit 0/0/0。
- 8 行顺序 = runner 硬校验列表：sel_basic / sel_override / sel_basic2_default / sel_allfail / emulfn_load_ok / emulfn_load_dataunavail / emulfn_channels / pipeline_env_note ✓（覆盖模型链四态 + loader 桥两态 + 错误通道六例 + 残留声明）。
- **错误原文与 Ghidra 常量逐字对照**：
  - `a/c1=err:Branch encountered emulating jumptable calculation` = jumptable.cc:129 逐字；
  - `b=err:Indirect branch encountered emulating jumptable calculation` = cc:135 逐字；
  - `d=err:Could not execute MULTIEQUAL` = emulateutil.cc:105 逐字；
  - `emulfn_load_dataunavail msg=Could not emulate address calculation at <A>` = cc:248 逐字（地址双侧规范化为 `<A>`，规避两套 Address 打印器差异，正当）；
  - `sel_allfail msg=Could not recover jumptable at <A>. Too many branches` = cc:2629 逐字；
  - `c0=ok:55`（cv3=0x55 CBRANCH not-taken 回读）、`e=ok:88`（cv5=0x88 经 MULTIEQUAL in-edge 解析成功）与 fixture 常量一致。
- **pins 三件套自洽（实测）**：runner 内嵌 git 对象 pin（base commit `185f0e9` / tree / src tree / jumptable blob / Cargo.toml|lock|build.rs blob）+ metadata comparand sha256 五项（cpp/rust fixture、jumptable overlay、**rangeutil overlay**、runner）与当前 worktree 文件 sha256 全部吻合（本复核逐一重算）；oracle 身份五重校验（HEAD=tag=commit、cpp tree、language tree、Makefile blob + dirty check）；input（examples/curl blob）与 assets（sla/pspec/cspec/ldefs blob+sha256+size、BFD header/library sha）全 pin；`input_manifest.sha256` 规范化指纹校验；coverage/residuals/known_diffs 交叉一致性（MATCH 不得带 residual、known_diff 前缀必须出现且解释全部差异行）在 runner 内机器强制。
- **诚实性**：`projection_status/overall_status=MISMATCH`（pipeline_env_note 绑定 residual JUMPTABLE-PIPELINE-0001），未夸大为 MATCH，符合机制 B2。
- Rust 侧错误消息源（src/jumptable.rs:4990/4997 等）逐字存在。

## 7. 清单 6 — Result 签名对段2/段3 契约完备性 ✓
- `JumpModel::recover_model/build_addresses` trait 签名改 `Result<_, JumpTableRecoveryError>`，13 处（trait + 7 impl × 2）全量迁移，无半迁移状态。
- `JumpTableRecoveryError{Thunk,Lowlevel}` + `recovery_mode()`（→FailThunk/FailNormal）精确映射 stageJumpTable 双 catch（funcdata_block.cc:539-544）；消息文本保留完整，段2 可重放 `warning(err.explain,addr)` 副作用——truncated_flow/RecoveryMode 所需 mode 1/2 区分契约就绪。
- 旧调用方不破坏：flow.rs:780/2597 走 `try_recover`（Option adapter）、funcdata.rs:7500 走 `recover_addresses`（bool adapter）；新入口 `recover_addresses_classified`/`try_recover_classified` 供段2/段3 切换。adapter 明确标注 RUGRA-GLUE。
- DataUnavail→Lowlevel 转换在 `emulate_path` 内完成（cc:246-250 语义：就地捕获 DataUnavailError 转带地址 LowlevelError、其余穿透），与 Ghidra 异常家族层次（DataUnavailError ⊂ LowlevelError, loadimage.hh:31）一致。

## 8. 非阻断建议

| # | 建议 | 依据 |
|---|---|---|
| A | rangeutil.rs `CircleRange::next` 的 `// Ghidra: rangeutil.cc:179/181` 注释与 docs/api/rangeutil.md 对应文案改为 `rangeutil.hh:82`（getNext inline 定义处）；get_size 引用 cc:256-273 已正确，保留 | 机制 D cited-line-drift；本复核 §2.3 |
| B | JUMPTABLE-HYGIENE-0001 中补记 is_load_in_path 第三条件的**可观测差异描述**（sz==256 ∧ size==1 ∧ load-in-path：Rugra 采纳候选 varnode，Ghidra 不采纳） | §3.6；grep 证实 Ghidra 无 isLoadInPath |
| C | `emulate_path` 中 MULTIEQUAL 判定改用 startop 自身 opcode 或先判 `i==num_ops`，消除 startop 不在 meld 时 `path_meld.get_op(i)` 的越界 panic（Ghidra 用 `startop->code()` 恒安全并落到 "Bad jumptable emulation" throw）。当前调用链（startop 恒来自 meld）不可达，段2 扩大调用方前应修 | jumptable.rs:5191 vs cc:222 |
| D | sanity_check 的 loadpoints 收缩：Ghidra `resize(loadcounts[i-1])` 可增可减（增时零填），Rugra 仅 `keep<=len` 时 truncate。正常路径 keep≤len 恒成立不可观测；如需逐字可在段2 补 | jumptable.rs:3170-3177 vs cc:1605-1608 |
| E | JumpAssisted payload（JumpAssistOp calc/addr 脚本）fail-closed 为声明缺口（本 commit 函数头 + metadata `jumpassist_payload=NO_ORACLE`）：真实 jumpassist userop 二进制上 Rugra 将拒绝并大概率落 "Too many branches"，与 Ghidra 成功建表不等价。段2/后续需在含 jumpassist 的语料上开 TODO 复核 | cc:2111-2122 未移植 |
| F | build_addresses 的 `addressToByte` 以 `word_size==1` 固化（单空间模型，代码内已注明 P1 文档化分歧）；Address 增加 space 字段后回收 | cc:1448-1453 vs jumptable.rs:2872-2878 |
| G | execute_segmentop 统一走 Lowlevel "Segment operand missing definition"（保守降级，函数头已注 TODO JUMPTABLE-PIPELINE-0001）；x86 语料不可观测，段3 前清账 | emulateutil.cc:123 |

## 9. 门禁健康旁注（机制 F，只读观察）
worktree `ghidra` symlink → 主仓 oracle（HEAD 与锁定 commit 一致性由 runner 五重校验背书）；本 commit 含 `## Alignment Evidence` 块且四类语义逐项成文；`src/*.rs` 改动同 commit 更新 `docs/api/{jumptable,rangeutil}.md`；核心算法白名单模块 jumptable.rs 本复核即机制 C 要求的独立复核，本报告为 `## Cross-Review: APPROVE` 依据。租约外 rangeutil.rs 已由本报告 §2 明确追认，请 root 在集成 commit 中引用本报告编号。

## 10. 结论

段1 范围内（模型选择链、find_normalized 调用形态与 readonly 救援、EmulateFunction loader 桥与类型化错误通道、maxtablesize 接线、Basic2 initializeStart、set_override）逐项与锁定 oracle 12.0.4 对齐；双侧 fixture 8/8 字节一致且 pins 机器强制自洽；Trivial 回退删除经全文 grep 证实正当；fail-closed 契约等价性论证成立；rangeutil.rs 伴随修复确为必要且最小的对齐修复，**予以追认**。遗留项均绑定已登记 TODO（JUMPTABLE-PIPELINE-0001 段2/3、JUMPTABLE-HYGIENE-0001）或本报告建议清单，无一为未解释差异。

**Cross-Review: APPROVE**
