# R16 — MERGE-FORCEMERGE-PANIC-0001 独立复核报告

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-merge-forcepanic`，分支 `agent/merge-forcepanic`
- 复核 commit：`8dc17e4`（fix: ActionMergeType runs mergeByDatatype only）+ `2d5fe96`（test: pin merge_forcepanic_1204 bilateral oracle fixture）
- 复核方式：独立打开锁定 oracle（`ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`，已验证）逐行读原文；只读 worktree/git；compare 工具只读运行
- 复核日期：2026-08-25
- 结论：**Cross-Review: APPROVE**（附 5 条非阻断建议）

---

## 1. 根因链验证 — 成立

### 1.1 Ghidra 原文（逐行亲读）

**coreaction.hh:409-416（ActionMergeType）**：

```cpp
virtual int4 apply(Funcdata &data) {
  data.getMerge().mergeByDatatype(data.beginLoc(),data.endLoc()); return 0; }
```

apply 体（414-415）**仅一步** `mergeByDatatype(beginLoc(),endLoc())`，返回 0。无任何对 mergeAddrTied/mergeRangeMust 的调用。

**coreaction.cc:5717-5729（universalAction 管线序，grep 逐行确认）**：

```
5717 ActionAssignHigh        5722 ActionMergeCopy
5718 ActionMergeRequired     5723 ActionDominantCopy
5719 ActionMarkExplicit      5724 ActionDynamicSymbols("dynamic")
5720 ActionMarkImplied       5725 ActionMarkIndirectOnly   // "Must come after required merges but before speculative"
5721 ActionMergeMultiEntry   5726 ActionMergeAdjacent
                             5727 ActionMergeType
```

5720 行注释原文：`// This must come BEFORE general merging`。mergetype（5727）在 markimplied（5720）之后 7 个槽位。

**mergeAddrTied 全库唯一 Action 调用点**：`grep -rn mergeAddrTied *.cc *.hh` 仅 3 处——merge.hh:127（声明）、merge.cc:609（定义）、**coreaction.hh:370（ActionMergeRequired::apply 内，与 groupPartials/mergeMarker 同行）**。Ghidra 中 mergeAddrTied 在主管线**有且只有 mergerequired 一次**，时序上必在 markimplied 之前。

**merge.cc:241-247（mergeTestMust）**：

```cpp
void Merge::mergeTestMust(Varnode *vn)      // 241
{
  if (vn->hasCover() && !vn->isImplied())   // 244
    return;
  throw LowlevelError("Cannot force merge of range");  // 246
}
```

panic 文本逐字吻合。调用链：mergeRangeMust（merge.cc:301-318，305/313 两处 mergeTestMust）← mergeAddrTied（merge.cc:634）。故 **markimplied 之后重跑 mergeAddrTied 必然**使 implied 成员到达 mergeTestMust——Ghidra 不可达状态。

### 1.2 Rust 修复语义等价

`8dc17e4` diff（src/coreaction.rs:1088 区）：`merge.merge_all(fd)` → `merge.merge_by_datatype(fd)`，返回 `NO_CHANGE`（=0，对齐 Ghidra `return 0`）。apply 单步化后与 coreaction.hh:414 逐字对应。

修复正确性的结构验证：merge_all 单体（merge.rs:764）曾在 mergetype 内重跑的 8 个步骤（merge_addr_tied/merge_required/merge_opcode(COPY)/dominant/adjacent/hide_shadow/copy_marker 等）**全部**由 Rust 主管线独立 Action 承接——src/action.rs:2163-2175 注册序与 Ghidra 5717-5729 逐行对齐（`mergerequired :5718 … mergetype :5727 — the single instance`），且有 `test_post_cleanup_sequence_matches_ghidra_5714_5738` 锁定。ActionMergeRequired::apply（coreaction.rs:946-953）正确承载 mergeAddrTied+groupPartials+mergeMarker 三连（对齐 coreaction.hh:370）。

## 2. merge_all 退役影响面 — 无残留依赖

- 修复后 `grep merge_all src/*.rs examples/*.rs`：非注释命中仅 merge.rs:4401/4459/4571，全部位于 `#[cfg(test)] mod tests`（merge.rs:4365 起）。**主管线零调用点依赖其多步行为。**
- merge.rs:3549 `merge_by_datatype` 与 merge.cc:359-401 抽验等价：
  - 遍历：`for vn_ref in &fd.vbank.loc_tree` ↔ merge.cc:371 `for(iter=startiter;iter!=enditer;++iter)`（行号 grep 确认 371）。
  - 过滤：free → mergeTestBasic → mark-dedup（Rust 顺序 free→basic→mark，Ghidra free→mark→basic；三者均为无副作用纯谓词 continue，行为等价）。
  - 分组键：`Arc::ptr_eq(&datatype, &high.v_type.get())` ↔ merge.cc:392 `if (ct == high->getType())`（精确 Datatype 指针恒等，行号 grep 确认 392）。
  - 异型回插（VecDeque push_back）与 Ghidra `++hiter` 跳过保持剩余项相对顺序，外层取队首等价。
  - `mergeLinear` 承接（merge.rs:3608，对齐 merge.cc:272-292）；三个谓词 merge_test_required/adjacent/speculative（merge.rs:1387/1505/1545）与 merge.cc:103-172/175-218/220-233 **逐行对齐**，且 Ghidra 侧 mergeTestSpeculative 注释明确 "not Cover related"——cover 相交在实际 merge 调用内，两侧结构一致。
  - Rust 分组前的 `update_type()` 为 Rugra 懒类型胶水，非本次改动（merge.rs 零 diff）。

## 3. 租约外溢判定 — 最小必要，正确

任务租约写 merge.rs，实改 coreaction.rs 一处调用点（14 行中 11 行是文档注释）。判定：**缺陷根因在调用点**（ActionMergeType::apply 误调遗留 merge_all 单体，f4be0bb 引入），merge.rs 各被调函数自身忠实（见第 2 节抽验）。merge.rs 不改为正确决定；改动范围（1 个调用点 + docs/api/coreaction.md 同步 9 行）满足铁律 3 的同 commit 文档更新。主仓 TODO_BOARD 行 24 已披露并裁定该外溢（"merge.rs 忠实无需改"）。

## 4. fixture 负控制与鉴别逻辑 — 自洽

### 4.1 双侧对称性

- prestate（两侧同构）：b0 内 r0 `COPY(const4:5)→a1`、r1 `SUBPIECE(const8,0)→s1`（a1/s1 同为 stack:0x100 4 字节 exact-location cluster，经 production newVarnodeOut 路径后**清除 addrtied|mapped tail**，即 mergerequired 单次 pass 时 ungated）、r2 `INT_ADD(s1,const4:7)→t2`(unique)。cpp 侧 175 行 `vn->clearFlags(Varnode::addrtied|Varnode::mapped)`，rust 侧 raw bank 路径不装 tail。
- install 时序：双侧均在 markindirectonly 之后、mergeadjacent 之前对 a1 装 addrtied|mapped（cpp 345 `a1->setFlags(...)`，rust `flags |= ADDRTIED|MAPPED`），输出 `install=addrtied:mapped:a1` 行位置相同 → markimplied 已把 s1 标 implied、mergetype 即将运行前簇已 gated——与 05b6b44 触发链（markimplied 后存在 implied+addrtied 同簇）在 decisive 维度一致。
- 异常通道同构：cpp `action->perform()` + `catch(LowlevelError)`（exc=error.explain，verdict=PIPELINE-THREW）；rust `perform_child` + `catch_unwind`（exc=payload，verdict=PIPELINE-THREW）。exc!=none 即 break，break 后双侧同打 post/verdict。

### 4.2 负控制翻转的逻辑必然性（静态推导）

Rust 侧：`merge_addr_tied = try_merge_addr_tied(fd).unwrap_or_else(|e| panic!("{e}"))`（merge.rs:914-917，panic 点 :916:37）→ `merge_test_must` 对 implied 成员返回 `Err(anyhow!("Cannot force merge of range"))`（merge.rs:1689，文本对齐 merge.cc:246）。若 apply 回退 merge_all：其 Step 1a 重跑 merge_addr_tied → 簇 {a1(ADDRTIED), s1(implied)} → merge_range_must → merge_test_must(s1) Err → panic → catch_unwind 捕获 → `act=mergetype|exc=Cannot force merge of range`、`verdict=PIPELINE-THREW`。翻转必然。修复前基线 `/tmp/rugra-reports/e2e-postbreakpool.stderr` 实录 3 次 `panicked at src/merge.rs:916:37: Cannot force merge of range`，与 commit 声明 "was 3" 互证。

### 4.3 runner 鉴别链（tools/run_merge_forcepanic_oracle.sh，218 行）

1. oracle 四重身份（commit/tag^{} /cpp tree/Makefile blob）+ dirty check；
2. Rugra base 四重钉（commit/tree/src tree/coreaction.rs blob id）；
3. comparand 哈希（cpp/rust fixture/runner sha256）+ input_manifest canonical-JSON sha256；
4. 隔离重建（git archive 至 mktemp 快照，oracle 从锁定 tree 重建 libdecomp.a；flock 共享 cargo 锁）；
5. 输出判定：exit!=0 或 stderr 非空即败；逐行对比——**未登记差异行 → SystemExit**；已登记行须匹配注册的 rust_line_sha256（防漂移）；`verdict=PIPELINE-OK` 须唯一、`act=mergetype|res=0|exc=none` 须存在。terminal 输出 `decisive_projection=MATCH registered_mismatch=1 overall=MISMATCH`。

**离线复算**：cpp/rust fixture、runner 三文件 sha256 与 metadata 注册值逐字节一致；input_manifest canonical sha256 重算匹配（`5bddd7cb…`）。fixture 输出结构：7 个打印点 = schema+seq+pre+11×act+install+post+verdict = **17 行**，与 runner/commit 声称一致。

## 5. 新登记缺口事实核实 — 均成立（行号引用有偏差，见建议 1）

### 5.1 COREACTION-MARKIMPLIED-COUNT-0001 — 事实成立

- Ghidra `ActionMarkImplied::apply` 定义于 coreaction.cc:3416（grep 确认）；DFS pop 处 **coreaction.cc:3434** `count += 1; // Will be marked either explicit or implied`（每个被标记 explicit/implied 的候选各 +1）。
- `Action::perform`（action.cc:298）`count = 0` → `res = apply(data)` → 尾部 **action.cc:362 `return count;`**；markimplied 构造带 rule_onceperfunc、无 rule_repeatapply，故 apply 一次后 perform 返回 count=1。fixture 观察 `act=markimplied|res=1` 正确。
- Rust：coreaction.rs ActionMarkImplied::apply 计了 `change_count` 但 `if change_count > 0 { Ok(NO_CHANGE) } else { Ok(NO_CHANGE) }` **两分支相同**，恒报 res=0。登记 MISMATCH + todo 派修正确；fixture 的 implied 分类本身（s1 im=1）双侧 MATCH。

### 5.2 COREACTION-BASEEXPLICIT-NUMINST-0001 — 事实成立

- Ghidra `ActionMarkExplicit::baseExplicit`（coreaction.cc:3007）：**coreaction.cc:3021** `if ((high!=(HighVariable *)0)&&(high->numInstances()>1)) return -1; // Must not be merged at all` —— 多实例 High 成员直接判 explicit，位于 addrtied 规则（3022 起）**之前**。
- Rust `base_explicit`（coreaction.rs:2866）：从 call 检查直接跳 `vn.is_addr_tied()`，**无 numInstances 检查**；且 addrtied 分支为 "Simplified: addr-tied → explicit"（无 Ghidra 的 SUBPIECE/loneDescend/ZEXT/PIECE 细化，3007-3062）。缺口事实正确。
- fixture UNTESTED 判定合理：ungated 形状使 highs 在 markexplicit 时保持 single-instance（mergerequired 跳过该簇），3021 规则不被两侧触发，升 MATCH 不成立。

## 6. 三函数恢复声明与产物一致性 — 全部精确复现

对 `result/curl_cur.c`（05:54 回流，晚于两 commit）实跑 compare（只读）：

| 函数 | 声明 | 复现 |
|---|---|---|
| my_get_line 0x3840 | diff=168 defects=0 | 168 / 0 ✓ |
| helpf 0x3980 | diff=143 defects=1 | 143 / 1 ✓ |
| file2string.part.0 0x3a90 | diff=143 defects=1 | 143 / 1 ✓ |
| my_get_token | 94 | 94 / 0 ✓ |
| 全局 | skeleton 2409 / defects 2 / numbering 1 | 2409 / 2 (in 2/123) / 1 ✓ |

三函数在产物中均有完整函数体（curl_cur.c:621/757/860）。修复前基线 3 panic（e2e-postbreakpool.stderr）与 "was 3" 一致；`## Differential` 块按机制 B 完整解释全部缺陷（helpf/file2string pre-existing empty-else、match_url numbering pre-existing）。主仓 TODO_BOARD 行 24-26 已由 root 登记（REVIEW/QUEUED 状态），铁律 3 满足。

---

## 裁定

### Cross-Review: APPROVE

四类决定性语义独立核对：
- [x] 引用/输出参数：apply 仅经 data.getMerge() 突变 Funcdata，无其他输出参数，返回 0/NO_CHANGE 对应
- [x] 循环边界/遍历顺序：mergeByDatatype 单遍 beginLoc..endLoc（371）；管线序 5717-5729 逐行对齐且有测试锁定
- [x] 计数器/累加器：apply 无计数器；markimplied 的 count+=1 缺口被正确登记而非掩盖
- [x] 排序/比较键：类型分组精确指针恒等（392 ↔ Arc::ptr_eq）；mergeLinear 按 compareHighByBlock 排序

### 建议（非阻断）

1. **行号引用修正**（机制 D cited-line-drift 预防）：TODO/metadata 的 `coreaction.cc:3426/3454`（count+=1 实际在 **3434**；3426 是 `vn = *viter;`，3454 是 apply 的 `return 0;`）与 `3022-3023`（numInstances 规则实际在 **3021**；3022-3023 是 addrtied+SUBPIECE 开头）。事实无误，root dispatch 时应改正引用行，避免后续按错行移植。
2. metadata observation 段 "10 act lines" 系笔误：11 个 child 产生 11 行 act（总数 17 行不变，runner 一致）。
3. fixture 注释称 install 模拟 "ActionDynamicSymbols' setSymbolProperties lands it between markimplied and mergeadjacent"，但真实管线 dynamicsymbols 槽位在 5724（markindirectonly 5725 之前）；fixture install 在 markindirectonly 之后。对 decisive contract（mergetype 不重入 mergeAddrTied）无影响且双侧同构、负控制可鉴别，建议注释改为"markimplied 之后、mergeadjacent 之前"的抽象时序表述。
4. Rust ActionMarkImplied::apply 的双分支同返 NO_CHANGE（count 桥未接）与 DFS→静态 cover 的近似（注释自认 conservative for rare chained implications）属既有债务，已登记/待登记项应与 D2 链任务对齐，勿随本 APPROVE 视为已闭合。
5. `merge_all` 单体仍导出（pub）且仅测试使用，后续 wave 可考虑降私有或标注 legacy，防止再次被管线误接。
