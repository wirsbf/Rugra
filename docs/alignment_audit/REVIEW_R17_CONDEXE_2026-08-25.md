# R17 — CONDEXE-SUCCESS-STATE-0001 独立复核（机制 C）

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-condexe` 分支 `agent/condexe-success-state`
  commits `2743440`（align）+ `e5db503f`（evidence），parent `b4fe1a17`。
- 复核人：独立复核 Agent（自己读 Ghidra 原文，未采信实现者 Alignment Evidence 声明）。
- Oracle 身份亲验：`ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b` = 锁定 commit，
  cpp tree / Makefile blob 由 runner 亲验（本复核另用 `git rev-parse` 抽验 commit 一致）。
- 复核方式：只读 worktree/git；Ghidra 原文全文亲读（condexe.cc 全文 + funcdata_varnode.cc:95-135
  + funcdata.hh:225-250 + heritage.cc:179-204/2655-2680/2760-2800 + heritage.hh:110-200
  + block.cc:1000-1140/1540-1660/2194-2215 + funcdata_block.cc:704-745/860-900
  + space.cc/heritage 构造器 flags + typeop.cc branch/returns flags + op.hh:185-189）。
  未运行 cargo（按指令禁止）；哈希用 sha256sum/git rev-parse 亲算。

## 结论：Cross-Review: APPROVE（4 条非阻断「建议」见文末）

四个被移植函数（buildHeritageArray / testRemovability cc:392 门 / doReplacement RETURN 腿 /
ActionConditionalExe::apply）经逐行独立对照，四类决定性语义全部 MATCH；fixture 双侧门禁自洽且
所有可本地验证的哈希 pin 全部通过。发现的问题均为文档/流程层（错误叙事注释、TODO/roadmap 未同步），
不影响行为对齐。

---

## 1. 四类语义逐项核对（独立读 oracle 后对照）

### 1.1 buildHeritageArray（condexe.cc:23-37 → src/condexe.rs:167）

oracle 原文（亲读）：
```cpp
heritageyes.clear();
heritageyes.resize(glb->numSpaces(),false);
for(int4 i=0;i<glb->numSpaces();++i) {
  AddrSpace *spc = glb->getSpace(i);
  if (spc == (AddrSpace *)0) continue;      // baselist hole
  int4 index = spc->getIndex();
  if (!spc->isHeritaged()) continue;        // cc:33 过滤在前
  if (fd->numHeritagePasses(spc) > 0)       // cc:34 查询在后
    heritageyes[index] = true;
}
```

- **引用/输出参数**：`heritageyes` 是成员，构造器（cc:432-437）缓存一次；`fd->numHeritagePasses`
  是 funcdata.hh:237 内联委派 → `Heritage::numHeritagePasses`（heritage.cc:2793-2801，
  `return pass - info->delay;`）。Rugra `fd.heritage.num_heritage_passes(*spc)`
  （heritage.rs:5632 区域，`self.pass - delay`）同一委派目标，直读等价。✓
- **过滤序是承载语义的（非风格）**：`Heritage::numHeritagePasses` 对 non-heritaged 空间
  **throw LowlevelError**（heritage.cc:2786-2787，HeritageInfo 构造器把 non-heritaged 空间
  置 `space=(AddrSpace*)0`，heritage.cc:179-204 亲读）。因此 cc:33 必须先于 cc:34，否则 oracle
  崩溃。Rugra `build_heritage_array`（condexe.rs:173-181）`is_heritaged()` 先 continue，
  `num_heritage_passes` 后查 —— 顺序正确，且 throw 路径同样不可达。✓
- **计数器/累加器**：全 false 起始（`vec![false; 7]` = `resize(numSpaces,false)` 替身），仅
  `numHeritagePasses>0` 翻位。逐空间独立，无跨空间交互 → 迭代顺序不可观测。✓
- **排序/比较键**：oracle 按 `spc->getIndex()`（baselist 槽位）索引、按槽位 i 遍历（两者同源
  但独立取值）；Rugra 读写两侧同经 `condexe_space_index`（表内位置 = getIndex 替身），内部自洽。
  读取侧（test_removability condexe.rs:462-466）对 Overlay/Other（表外）`None → return false`，
  等价 oracle `heritageyes[other_idx]==false`（Other/Const/Join/Iop/Fspec 均被 cc:33 拒绝，
  永不置 true；FspecSpace 非可继承经 fspec.cc:2119 亲证）。✓
- **固定表替身的覆盖性**：Ghidra 可继承空间全集 = spec 空间（ram/register/stack，space.cc:78/95
  默认 on）+ unique；非可继承 = const/other/join/iop/fspec（space.cc:359/399/406/451、op.cc:36、
  fspec.cc:2119 亲证）。`CONDEXE_SPACE_LIST` 7 项覆盖全部可继承空间 + 全部非可继承固定空间，
  与 `Heritage::build_info_list`（heritage.rs:660）同表。缺口仅 Overlay 动态空间（SPACE-0001
  已登记，代码注释如实声明）。✓

### 1.2 testRemovability cc:368-392（→ src/condexe.rs:426-470）

- oracle 的 `heritageyes` 门**只在 else（非 MULTIEQUAL）分支**（cc:392）；cc:368 MULTIEQUAL 分支
  只做 testMultiRead。Rust 同构（429-436 无门，456-467 有门）。✓ fixture S4 注释也如实记录。
- 门语义：`hasnodescend && (!heritageyes[vn->getSpace()->getIndex()]) → return false`。
  Rust：`hasnodescend` 初 true、每后代置 false，随后按空间索引查数组，表外空间 false。✓
- 检查顺序：oracle cc:377 `isFlowBreak()||isCall()` → cc:378 LOAD/STORE → cc:380 INDIRECT →
  cc:383 isAddrTied → 后代循环 → cc:392 门。Rust 顺序 is_call → flow-break → LOAD/STORE →
  INDIRECT → addr_tied → 后代 → 门。isFlowBreak 与 isCall 为不相交 opcode 集上的纯谓词、同返
  false，交换不可观测。`isFlowBreak` = branch|returns（op.hh:189 亲读）= {BRANCH,CBRANCH,
  BRANCHIND,RETURN} —— Rust 枚举同集。✓
- `verify`（condexe.rs:497-505）正序跳过 branch 测其余，oracle（cc:418-426）逆序测 all-but-last：
  testRemovability 是纯谓词无突变，集合相同（最后一 op 必为 CBRANCH，testIBlock 保证），
  AND 顺序无关。✓
- `execute`（condexe.rs:930-958）逆序销毁全部 op（含 branch，跳过 do_replacement）；oracle
  `isBranch()`（branch flag，op.hh:185 + typeop.cc:586/605/649）**不含 RETURN**（RETURN 只有
  returns flag，typeop.cc:878），Rust 的 is_branch 含 RETURN —— 但 CBRANCH 终结的基本块中
  RETURN 不可能出现在 CBRANCH 之前（流破坏 op 恒为块尾），不可达状态上无分歧。✓
  （列「建议」D。）

### 1.3 apply 的活遍历 + numhits→count（condexe.cc:478-503 → src/condexe.rs:1718-1770）

oracle 原文亲读要点：
- cc:485-486 unreachable 前置 return（count 不动、零突变）→ Rust 1726-1728。✓
- cc:487 **一个** ConditionalExecution（buildHeritageArray 每 apply 缓存一次）→ Rust 1732。✓
- cc:488 `const BlockGraph &bblocks(...)` 活引用；cc:492-493 `i<bblocks.getSize()` 与
  `bblocks.getBlock(i)` **每次迭代活读** → Rust 1740/1743 经 `condexe.fd.bblocks` 活读。✓
- 无预过滤（检查全在 trial/verify 内）→ Rust 1744-1757 无任何 2in/2out/CBRANCH 预滤。✓
- numhits 每 execute+1（cc:496→1755）、changethisround 同步（cc:497→1756）、
  **`count += numhits` 仅轮循环后一次**（cc:501→1768）、return 0（→NO_CHANGE）。
  Err 上抛跳过累加 = oracle throw 跳过（异常协议 CONDEXE-ERROR-0006 一致）。✓
- **活语义的真实内容比"列表左移"更强（实现者证据块描述不完整，但代码正确）**：
  `Funcdata::removeFromFlowSplit`（funcdata_block.cc:881-889 亲读）= edges 重连 →
  `bblocks.removeBlock(bl)` → **`structureReset()`** → `structureLoops`（block.cc:2194-2215）
  → `findSpanningTree` 末尾 **`list = rpostorder`（block.cc:1135）**。即每次折叠后整表**重排为
  RPO**，非仅删除左移。Rust 侧完全同构：`remove_from_flow_split`（funcdata.rs:2891-2952）→
  `remove_block_arc` + `structure_reset`（funcdata.rs:2402）→ `structure_loops`（block.rs:3263）
  → `find_spanning_tree` 末尾 `self.blocks = rpostorder`（block.rs:2097-2102）。✓✓

### 1.4 doReplacement RETURN 腿 + 共享 helper（condexe.cc:339-349 → src/condexe.rs:852-891）

- oracle cc:343 `fd->newVarnodeOut(retvn->getSize(),retvn->getAddr(),newcopyop)`：
  `getAddr()` 携带 (space,offset)，`newVarnodeOut`（funcdata_varnode.cc:104-127 亲读）经
  `vbank.createDef(s,m,ct,op)` 保留空间。cc:182 pullbackOp 用**同一 helper、同一地址来源**
  （`origOutVn->getAddr()`）—— 两条腿在 oracle 中本就共享语义。Rust 抽出
  `new_varnode_out_with_space`（condexe.rs:612-631）两处共用（578 pullback、877 RETURN），
  逐语句镜像 funcdata_varnode.cc:104-127：createDef→setOutput→assignHigh→
  `size>=minLanedSize` 时 checkForLanedRegister→properties 腿。✓
- RETURN 腿语句序完全一致：newOp(1,readop.addr)→COPY→newVarnodeOut→`opSetInput(readop,outvn,1)`
  →`opInsertBefore`→readop:=newcopy/slot:=0→getReplacementRead(op,**原 bl**)→opSetInput(,rvn,0)。
  `bl` 在 reassign **之前**捕获（condexe.rs:831-833 注释点明，cc:330/346 的关键序）。✓
- 负对照成立：旧实现 `new_varnode_out` pin Register → S3 将打印 `register:0x2000`，
  pin 值 `unique:0x2000:4` 判别。✓
- `set_varnode_properties` 是 queryProperties/SymbolEntry 腿的 best-effort 替身（预存基础设施
  缺口，非本次引入；对 unique 空间 fixture 输入为 no-op，与 oracle 在该输入下行为一致）。

## 2. live vs 快照等价性主张 — 独立验证（复核清单第 2 项）

**先确认实现形态**：最终代码是真活读（1.3 节），roadmap 行 109 亲证旧实现是"快照 + 预滤 +
每轮重建"，本 commit 移除。因此 live/snapshot 等价性主张**不再承载任何对齐论证**——Rugra 与
Ghidra 执行同一算法，等价由构造成立，不靠论证。

**主张本身的独立检验**（"对良构钻石，RPO 中被折叠 iblock 的后继必是其自身 1in/1out 路径块，
索引 skip 不可能搁浅 trialable 块"）：

(a) **对 S2 fixture 图形为真，但理由与措辞均有误**：relist 不是"删除左移"。我手工模拟了 S2 全程
  （初始 RPO=[b0,b2,b1,b3,b7,b6,b8,b10,b9,b4,b12,b11,b13,b15,b14,b5,b17,b16,b18]，与 metadata
  pin 的 pre 前缀 b0,b2,b1,b3,b7,b6 逐项一致）：round 1 折叠 A(i=3)→relist 后游标 4..8 折叠
  B(i=8)→relist 后游标 9..13 折叠 C(i=13)；三次被本轮跳过的块分别是 b7/b12/b17（三个 postb，
  均 1in/1out）——但注意 A 折叠后 relist 把 b7 从 idx4 挪到 idx2（b1/b7 交换），"被跳过的块"
  是**新列表中落在游标下方的块**，不是"旧列表中 iblock 的后继"（旧后继 b7 被跳过、游标实际
  读到的是旧 idx5 的 b6）。

(b) **一般图形下主张为假（反例构造成功）**：verify/findInitPre 只约束 iblock 的**入侧**链为
  1in/1out，**出侧无任何约束**。取 ib1 的 out(0) 直指 T，T 自身是 2in/2out CBRANCH 块（另一条
  边来自别处，如另一钻石路径汇入）。旧 RPO=[...,ib1(i),T(i+1),...]；折叠 ib1（直连 pa→T）后
  relist，T 落在新位置 i（pa 子树先被 DFS 探索）≤ 游标 → **T（trialable）本轮被搁置**，下一轮
  才折叠。Ghidra 同样如此（同一活算法）→ 无双侧分歧；但"不可能搁浅 trialable 块"作为一般命题
  被证伪。该错误叙事出现在 metadata.decisive_semantics/coverage 与 fixture 头注释中（见建议 A）。

(c) **2in/2out 折叠后的索引位移确实影响后续 trial 枚举**（本复核确认）：位移 = 删 1 + 全表 RPO
  重排，可改变游标后续读到/跳过的块集合，甚至改变折叠相对顺序（live 与 snapshot 在一般图形下
  **不等价**——被搁置块与后见块的先后可换）；S2 图形恰好不判别（metadata 自己也承认
  "fold order is invariant between the live loop and a per-round snapshot"——与 fixture 注释
  的"判别"说直接矛盾）。对齐由代码活读保证，不由 fixture 判别力保证。

## 3. pass-delay 委派等价（复核清单第 5 项）

- funcdata.hh:237：`int4 numHeritagePasses(AddrSpace *spc) { return heritage.numHeritagePasses(spc); }`
  —— 纯内联委派。Rugra condexe.rs:181 直呼 `fd.heritage.num_heritage_passes(*spc)`
  （heritage.rs `pass - delay`，delay 来自 HeritageInfo，HeritageInfo::new 从
  `space.get_delay()` 取值）。委派链等价。✓
- 差异：oracle 对 non-heritaged 空间 throw，Rugra 返回 `pass-0`；本调用方先过 `is_heritaged`
  过滤，不可达。✓
- 固定表替身（heritage.rs:660 build_info_list）与 CONDEXE_SPACE_LIST 同表；Rugra
  `Stack.get_delay()==1`、其余 0（space.rs:139-144 亲读）= fixture C++ 侧
  `SpacebaseSpace(...,dl=1,...)`（translate.hh:181 参数位）——S1 逐空间阶梯
  （ram/register/unique pass1 翻转、stack delay=1 pass2 翻转）双侧同值。✓
- `HeritageInfo::new`（heritage.rs:382-409）镜像 heritage.cc:179-204（非可继承空间
  delay 仍读自空间、hasCallPlaceholders=false；可继承空间 delay/deadcodedelay 读取 +
  IPTR_SPACEBASE→Stack）。✓

## 4. fixture 证据核对（复核清单第 4 项）

**可本地亲验的全部通过**：
- comparand 四哈希亲算一致：cpp_fixture `c057a677…`、rust_fixture `b838ce74…`、
  overlay `1c5e7c43…`（= HEAD src/condexe.rs sha256，且 HEAD blob `5cde46e8` =
  base_condexe_blob = 2743440 blob，即被测源 = 已提交源）、runner `4926c73d…`。✓
- expected_results 内部自洽：ghidra_stdout_sha256 == rugra_stdout_sha256（`dbe19349…`）、
  stderr 双侧 = 空串哈希 `e3b0…`、raw_diff = 空串哈希（相同文件 diff 为空）、exit code 全 0。✓
- 13 records：record_order 13 项 = S1×4(heritage)+S2×5(pre/ret/state/multi/edges)+S3×2(ret/
  return)+S4×2(ret/ret)；runner（330 行）内置顺序硬校验 + 空stderr 校验 + 全哈希校验。✓
- runner 严密性亲读：oracle 四重身份（commit/tag/cpp-tree/Makefile blob）+ 脏树检查 + Rugra
  源七重 git pin + snapshot 重建（archive 显式闭包 + hash 校验 overlay）+ 双侧真实构建
  （ghidra libdecomp.a from locked archive；cargo --locked --offline）+ 逐哈希断言。✓
- 6 投影/总 MATCH/零残差 与 coverage 六键一致；MATCH 强制空 residual（runner 校验）。✓
- C++ fixture 驱动真实 oracle API（apply public、CountProbe 子类读 protected count、
  `#define private public` 读 heritageyes、production structureReset）；Rust fixture 逐 case
  镜像（含 `fd.heritage.pass = pass` 直驱）。S2 19 块→终态 16 块自洽；pre 记录 RPO 前缀与我
  手工模拟一致。✓

**声明性证据（无法本地复跑，cargo 禁用；记录为已声明）**：
- 双侧执行 stdout 逐字节一致（哈希如上）与 6/6 MATCH：runner 结构支持该结论，metadata/commit
  message 一致陈述；本复核未重跑。
- 三个旧 fixture（error/pullback/trueout）行为保持：其 metadata（本两 commit 未触碰，
  parent 侧本就 overall=UNTESTED——非本次降级）仍 pin 旧 overlay sha（`c9a926…`/`6b19d8…`/
  `57188a…` ≠ 现 `1c5e7c…`，即承认的 stale pin）与旧 rugra_stdout 哈希
  （`f654d29…`/`5e48384…`/`44f6e9d…`）；"rebuild 后逐字节复现"仅有 commit message 声明，
  无独立产物留档、TODO 板无重钉登记行。列为建议 C（非阻断：重钉前 runner 会因 overlay 哈希
  失配而拒绝而非误判 MATCH，安全方向失效）。

## 5. 铁律 3 流程核对（非阻断，交主 Agent 集成前修正）

- `docs/api/condexe.md` 与 src 同 commit 更新 ✓（pre-commit 要求满足）。
- `docs/TODO_BOARD.md` 行 84 `CONDEXE-SUCCESS-STATE-0001` 仍 **BLOCKED/unassigned**（两 commit
  均未更新）✗。
- `ALIGNMENT_ROADMAP.md` 行 109 仍列本次已修复的四缺陷（"快照而非活图/不累加 count/缺
  buildHeritageArray/Register 强制"）为未修 ✗。
- 三个 sibling fixture 的 stale overlay pin 无登记的重钉 TODO 行 ✗（commit message 说
  "pending the standard root repin"，板上无对应行）。

## 建议（非阻断，按优先级）

- **A（应修，文档错误叙事）**：三处与 pinned 输出矛盾的错误叙事须更正——
  (1) fixture `.cc:339-342`（"skip B_ib in round 1 … A, C, B that a per-round snapshot cannot
  produce"；实际 round 1 内 A,B,C，pin 序 b8,b13,b18）；(2) fixture `.rs:8-9/511`（"folds A, C, B"）；
  (3) `docs/api/condexe.md` fixture 段（"12 记录"→13；"b8,b18,b13 判别快照实现（快照给 b8,b13,b18）"
  ——实际 pin 即 b8,b13,b18，S2 不判别 live/snapshot，metadata 自己承认 invariance）。
  同时把 metadata `decisive_semantics.loop_bounds_traversal_order` / `coverage.
  live_traversal_round_partition` 中"index skip can never strand a trialable block"的一般化
  措辞收窄为 S2 图形事实（一般反例见本报告 §2(b)：iblock 出边直指 2in/2out 块即可搁置一轮）。
- **B（随重钉批）**：`execute()`/`verify()` 的 is_branch 枚举含 RETURN 而 oracle `isBranch()`
  不含（typeop.cc:878 RETURN 只带 returns flag）——CBRANCH 终结块内不可达，无行为差异；建议
  注释声明或对齐为三 opcode 集 + isFlowBreak 四 opcode 集，免未来复用踩坑。
- **C（流程）**：TODO 行 84 置 DONE+证据 commit；roadmap 行 109 同步（condexe 成功通道四缺陷
  已闭合，RuleOrPredicate 端到端/directsplit 残留维持 L2 的理由更新）；登记三 sibling fixture
  的标准重钉 TODO。
- **D（低优）**：`test_removability` 中 is_call 与 flow-break 检查顺序与 oracle 相反（纯谓词、
  同结果，不可观测）；如追求逐语句同形可调序，不必强制。

## 复核方法局限

cargo 禁用 → 无法复跑双侧执行与 1609 单测声明；行为等价判定基于：代码逐行对照（双侧）+
全部可本地验证的哈希/pin 亲算 + 我对 S2 全程 RPO 的独立手工模拟（与 pinned pre/multi 记录
一致）。实现者声明未被采信的部分（双侧 stdout 一致、旧 fixture 复现）已在 §4 标注为 declared。
