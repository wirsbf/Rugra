# Lane AX — run-to-run 输出不确定性调查报告

- 日期: 2026-09-22
- 调查者: Lane AX subagent (fixer)
- 工作目录: /home/ls/Rugra(master),产物全部在本目录,repo 未改动
- 环境: 112 核,系统 load ≈ 110-115(重负载,天然调度压力)

## 0. 指纹

| 项 | 值 |
|---|---|
| HEAD | `9b22329416de9ecad3d39f061f570946c27b17ce` (merge: opStackLoad contain fix + merge isLeaf recursion bound) |
| 二进制 | `target/release/examples/curl_decompile`(2026-09-22 03:08 构建,晚于 HEAD commit 03:03,src 无未提交改动 → 与 HEAD 一致) |
| 输入 | examples/curl(默认门禁语料) |
| 复现产物 | `run1..7.{out,err}`(无特殊 env),`rs1..4.{out,err}`(RUGRA_RULE_STATS=1) |

## 1. 复现结论:**已复现(master 当前树,非 AO 中间态)**

16 次全量 run(7 次无 env + 4 次 `RUGRA_RULE_STATS=1` + 5 次复验),stdout 只有 **两个** 版本:

| stdout sha256 | 语义 | 出现次数 | 备注 |
|---|---|---|---|
| `2ff151b6…` | `uVar32 = uVar27;` 在 `uVar27 = uVar25;` **前** | 9/16 | run1,2,3,4,6,7, rs3,rs4, rep1 |
| `d46404c2…` | `uVar32 = uVar27;` 在 `uVar27 = uVar25;` **后** | 7/16 | run5, rs1,rs2, rep2,3,4,5 |

判定依据:
- 两种 hash 在 **两种 env 下都出现**(rs1/rs2 = d464,rs3/rs4 = 2ff1;rep 批 1:4)→ 不是 RULE_STATS 环境变量系统性切换,也不是 I/O 节奏系统性偏移;
- 差异 **恒为同一函数同一语句对**(bimodal、单一 locus,16/16 落在同一处),不是多处随机噪声 → 不是调度时机竞争的典型形态,而是 **单一二值决策点**;
- 概率 ≈ 44-56%(9:7,近抛硬币),符合 std `HashMap` RandomState(SipHash 每 process 重新播种)对一个近似对称 key 集给出两种桶序的形态。

### 差异 locus

函数:`getparameter_constprop_0`(getparameter.constprop.0 @ 0x3f00)。

`run1.out`(2ff1 侧,行 2343-2348):
```c
    uVar27 = uVar27;
    iVar31 = __xstat(1,nextarg,(stat *)(in_RSP - 0x588));
    uVar32 = uVar27;      /* ← A */
    uVar27 = uVar25;      /* ← B */
```
`run5.out`(d464 侧)同一位置 A/B 互换(A 移到 B 后,文本逐字节相同)。

两条 COPY 目标是 **不同 HighVariable**(uVar32 / uVar27),A 读旧版 uVar27、B 写新版 uVar27——它们的相对顺序由两个 COPY op 的 SeqNum(= 创建/插入顺序)决定,打印按块内 op 顺序输出。**这不是命名抖动,是 op 顺序抖动。**

### AO 场景对比
Lane AO 报告的"同树两次全量 run 1 行语句位置差"与本次复现形态一致(单语句位移)。当前 master(opStackLoad 集成后)**仍然复现**,窗口没有关闭。

## 2. 机制定位

### 2.1 为什么是"每进程随机"
`curl_decompile` 对 **每个函数 spawn 独立 worker 进程** 反编译(examples/curl_decompile.rs:4186 `run_isolated_worker(WorkerJob::Decompile…)`)。getparameter.constprop.0 的 C 输出产生于该 worker 子进程内;每个 worker 都是新进程 → std HashMap `RandomState` 重新播种 → 该函数内部的随机序容器每次 run 重新洗牌。与 driver 调度、机器负载无关(重负载下 bimodal 且 8/11 稳定一侧)。

### 2.2 候选源清单(按嫌疑排序)

#### ★ 候选 1(高置信,机制完全吻合): `src/merge.rs:3566-3591` `Merge::process_copy_trims`

```rust
let mut counts: HashMap<usize, (Arc<RwLock<HighVariable>>, u32)> = HashMap::new();  // :3566  key=Arc::as_ptr(high)
for trim in &self.copy_trims { /* counts.entry(key).or_insert_with(...).1 += 1 */ }   // :3571-3581
let multi: Vec<Arc<RwLock<HighVariable>>> = counts
    .into_iter()                        // :3584  ← HashMap 迭代 = RandomState 顺序
    .filter_map(|(_, (h, c))| if c >= 2 { Some(h) } else { None })
    .collect();
for high in &multi {
    self.process_high_dominant_copy(fd, high);   // :3590  ← 会插 op!
}
```

调用链每一步:
- `process_high_dominant_copy`(merge.rs:3501)→ `build_dominant_copy`(merge.rs:3305);
- `build_dominant_copy` 对不在公共 dominator 块内的组 `fd.op_insert_end(&new_op, &dom_bl)`(merge.rs:3362)**在块尾插入新 dominant COPY**;
- 若两个不同 high(如 uVar32、uVar27 两组 trims)的 dominant COPY 落在同一 dom 块,两者的 SeqNum 相对顺序 = `multi` 的迭代顺序 = **每进程随机**。

**Oracle 对照(逐行读过)**:Ghidra `Merge::processCopyTrims`(merge.cc:1415-1436)按 `copyTrims` **列表序** 遍历,first-seen 顺序 push `multiCopy`(cc:1420-1428),再按该顺序处理(cc:1430-1435)——确定,且与任何固定 hash 序都不同。因此 Rugra 这里 **同时是不确定性源 + Ghidra 遍历序偏离**(双重违规)。

**与 locus 吻合点**:
1. 差异语句恰是一对目标不同的 COPY(uVar32/uVar27),位于同一块尾(__xstat 调用后、下一个 if 前),符合两次 `op_insert_end` 的插入序竞争;
2. 函数有 4 参数 + 大量栈槽(in_RSP-0x4e8/-0x588/-0x590),merge_addr_tied(→ snip_reads → allocate_copy_trim,populate copy_trims,merge.rs:3549-3551 注明 2026-07-04 已接线)在此类函数必跑;
3. 两个版本的 stderr trace(剔除 [SYM]/[PREPASS]/时长归一化后)**逐行相同** → 分歧点在无 trace 日志的代码里,与 merge 深层一致;
4. 同类 bug 在本 repo 有前科:heritage.rs:5230-5243 `RUN-NONDETERM` 注释(HashSet 迭代 → MULTIEQUAL 创建序随机,当时以 sort 钉死)。

**限制**:未做插桩因果验证(repo 不可改);置信"高"而非"实证"。建议修复 PR 里加最小复现断言(见 §5)。

#### 候选 2(中,仅 driver 层请求序,当前良性): `examples/curl_decompile.rs:4081-4092`
`symbol_entries` / `string_entries` / `prototype_entries` 三个 Vec 直接 `symbol_table.iter()` / `string_table.iter()` / `prototype_db.iter()` 收集(注释自述"Preserve the exact iteration order used by the former HashMap clones")→ **随 driver 进程随机**。当前 worker 侧全部按 key 查找消费(add_symbol/add_string 入 keyed 表,examples/curl_decompile.rs:2503-2518;program_db 构建侧 string_starts 显式 sort,examples/curl_decompile.rs:2251-2252)→ 暂无 stdout 影响,但任何未来"按序消费请求条目"的改动都会把随机序漏进输出。且 driver 侧 `DebugGlobalDatabase` 是 BTreeMap(debugproto.rs:84)而 string/symbol/proto 是 HashMap——同层不同序纪律,属卫生债。

#### 候选 3(低,已证良性但形态危险,登记观察):
- `src/printc.rs:8171` `copy_map.keys()`(ptr-keyed HashMap)迭代做链式追解——每 key 独立收敛到同一不动点,顺序不敏感(当前);若将来加 depth 截断副作用或 tie-break 会变质。
- `src/printc.rs:8579` `use_count: HashMap<(space,off),u32>` — 仅 keyed 查询。
- `src/coreaction.rs:1363` CSE `seen` map — 迭代源是 ordered alivelist,仅 lookup。

#### 已排除(本轮核对过、不是源):
- 核心 bank:`op.rs:1550` `optree: BTreeSet`(SeqNum 序)、`op.rs:1552` `alivelist: Vec`、`varnode.rs:2817` `loc_tree: BTreeSet`;`PcodeOpRef::Ord` 按 SeqNum(op.rs:1470-1476)、`VarnodeLocRef::Ord` 按 (space,loc,size,class,def-SeqNum/createIndex)(varnode.rs:2651-)——值序,非指针序,确定。
- merge.rs:1903/4145、coreaction.rs:3569、varmap.rs:720 的 `HashSet<ptr>`:dedup-only(contains/insert),不迭代。
- merge.rs:2197-2209 `by_symbol` HashMap 迭代后 **显式按 SymbolNameTree 排序**(注释同样点名 HashMap 迭代风险)——这是候选 1 修复可参照的现成模式。
- 生产 heritage 路径 `place_multiequals`(heritage.rs:5001)全程 Vec/tasklist 序;off-production 直连路径的 df HashSet 已 sort(heritage.rs:5242-5243)。
- `ActionCse`、`find_all_into_copies`(merge.rs:3253,结尾还 sort)、`hide_shadows`、`gather_additive_base`、`rec_map`(coreaction.rs:7531,keyed lookup + 地址序外层)、`RuleMultiCollapse`(descend Vec)——均确定。
- 线程:src/ 内无生产线程(仅 test watchdog heritage.rs:6722、sleigh_ffi 一次性);worker 是进程隔离,单线程执行。
- **stderr 不确定但无害**:run1 vs run2 stderr 差 9470 行,来源 = [PREPASS] `prototype_db.iter().take(30)`(examples/curl_decompile.rs:4057)与 [SYM] `symbol_table.iter()`(examples/curl_decompile.rs:4136)——纯日志,且是候选 2 同一随机序的可见症状。注意机制 B 提醒过 compare 噪音与此相关。

## 3. 静态扫描 top 风险点(printc/varmap/merge 输出路径,只列不修)

| # | 位置 | 形态 | 现状 |
|---|---|---|---|
| 1 | merge.rs:3566-3590 | ptr-keyed HashMap `into_iter()` 驱动 op 插入序 | **活性 bug(本次复现的头号候选)** |
| 2 | examples/curl_decompile.rs:4081-4092 | HashMap 迭代序固化为请求 payload 序 | 潜伏(worker 侧均 keyed 消费) |
| 3 | printc.rs:8171 | ptr-keyed copy_map keys 迭代 | 顺序不敏感收敛,脆弱 |
| 4 | printc.rs:4057(examples) prototype_db.iter() → [PREPASS] 日志 | stderr 不确定(已实测 9470 行/对) | 日志层,污染差分噪音统计 |
| 5 | printc.rs:8579 / coreaction.rs:1363 / merge.rs:248 等 | HashMap/HashSet 仅 lookup/dedup | 良性,演化时需守纪律 |

## 4. 登记建议

**实证不确定性 bug → 建议新开 P0 ID**(差分门禁机制 B/B2 的可信度根基:golden 对拍要求 run-to-run 确定性,否则任何一次差异都无法区分回归 vs 掷硬币):

- 建议 ID:`DETERM-COPYTRIM-0001`(或沿用既有标签族 `RUN-NONDETERM-2`)
- 级别:P0(输出确定性 = 差分门禁前提)
- Ghidra: merge.cc:1415-1436 `Merge::processCopyTrims`
- Rugra: src/merge.rs:3558-3591 `Merge::process_copy_trims`
- 修复方向(顺带修遍历序对齐):镜像 cc:1418-1436——遍历 `copy_trims` 列表序,first-seen 去重(HashSet 只做 contains)+ 计数,≥2 的 high 按首次出现序处理;参照 merge.rs:2197-2209 的既有 sort/ordered-collect 模式或直接改 Vec 结构。
- 验收:curl_decompile 连跑 ≥10 次 stdout sha256 单值;修复后该函数输出应与 Ghidra oracle 的 copyTrims 首见序一致(不是任一固定序)。
- 附带项(可并入或另开卫生 TODO):
  - coreaction.rs:12936-12941 注释声称 `process_copy_trims` 是 "faithful no-op / copyTrims never populated" 已 **过期**(merge.rs:3549-3551 注明 2026-07-04 已接线),应更正,防止后来者据此误判该路径死代码;
  - 候选 2 请求序卫生(examples 4081-4092):改为排序后收集(symbol/string/prototype_entries 按 addr sort),一次消除 driver 级随机序来源。

## 5. 附:复现命令

```bash
cd /home/ls/Rugra
for i in $(seq 1 10); do
  target/release/examples/curl_decompile > /dev/shm/rugra-tests/sb-integration/rep$i.out 2>/dev/null
done
sha256sum /dev/shm/rugra-tests/sb-integration/rep*.out | awk '{print $1}' | sort | uniq -c
# 实测(2026-09-22,16 runs 累计):出现两个 hash,累计比例 9:7;diff 两个版本仅
# getparameter_constprop_0 内 A/B 两行互换。rep 批单次 5 连跑 = 1:4,波动正常。
```

最小因果验证(留给修复 agent,需改 repo):
在 `process_copy_trims` 内把 `multi` 迭代序反转为确定序(如按首见序)后重跑 10 次——若 bimodal 消失即实证;再按 merge.cc:1420-1435 语义定序以同时满足 oracle 对齐。
