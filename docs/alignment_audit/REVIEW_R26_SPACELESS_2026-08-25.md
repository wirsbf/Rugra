# R26 — Cross-Review: 8d9aaf66 FSPEC-SPACELESS-REMAINDER

- 复核对象: master `8d9aaf66cf3dffbace3de5b7843835d1a778c734`（align: space-aware
  unjustified_container/fillin_map_fallback）
- 复核 Agent: 独立复核（只读主仓；未采信实现方 Alignment Evidence，自行通读 Ghidra 原文）
- Oracle: `ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`（= 锁定 pin，已现场核验）
- 日期: 2026-08-25
- **判定: Cross-Review: APPROVE**（附 2 项非阻塞发现，见 §5/§6）

## 0. 复核范围与实际所读 Ghidra 原文

按铁律 1.1/机制 C，逐行读完（非签名行）：

| Ghidra | 内容 | 结论依据 |
|---|---|---|
| fspec.cc:1411-1424 | `ParamListStandard::unjustifiedContainer` 全文 | minSize 门/just 三分支/getContainer 回写 |
| fspec.cc:1638-1719 | `ParamListStandardOut::fillinMapFallback` 全文 | 两处 trial 查询/offmatch walk/best 键 |
| fspec.cc:248-283 | `ParamEntry::justifiedContain` 全文 | join 逐 piece walk + cc:269 空间守卫 |
| fspec.cc:295-328 | `ParamEntry::getContainer` 全文 | join piece 选择 + 对齐 round-up |
| address.cc:131-142 | `Address::justifiedContain` 全文 | cc:133 `base != op2.base → -1` |
| address.cc:153-165 | `Address::overlap` | cc:158 跨空间 -1（§6 用） |
| fspec.hh:196-285 | `ParamTrial` 全部内联（getAddress/setEntry/mark\*/operator< 声明） | trial Address 携带空间、setEntry(null,0) |
| fspec.cc:1893-1914 | `ParamTrial::operator<` 全文 | sortTrials 键 |
| fspec.cc:660-680 + 1180-1200 | `findEntry` + `populateResolver` | §4 A57 一致性 |
| fspec.hh:87-98,123-153 | flags 枚举 / `isExclusion()==(alignment==0)` | firstOnly 三条件 |
| type.hh:130-140 | `type_class` 枚举 | bestclass 序 |

## 1. 四类语义核对 — PASS

### 1.1 `unjustified_container`（src/fspec.rs:5572 ← fspec.cc:1411-1424）

- **引用/输出参数**: `res: &mut VarnodeData` 仅在 hit 行经 `get_container` 写入；
  miss 行不写（与 Ghidra 一致，fixture 的 miss 行 res sentinel 不读）。
  `get_container` 返回值同 Ghidra cc:1420 一样被忽略。`space: AddressSpace`
  显式线程化 = `const Address &loc` 携带空间的合法过渡形态（同 find_entry /
  assumed_extension 家族模式，注释已声明）。
- **循环边界/遍历顺序**: `for cur in &self.entry` 列表序全量；minSize 门
  （cc:1416）在 `justified_contain_in_space`（cc:1417 等价物）**之前**；
  just<0 continue / **just==0 整函数提前 false**（cc:1419 的 Ghidra 怪癖，
  忠实保留）/ 否则首个命中 getContainer+true。
- **计数器/累加器**: 列表级无；join walk skip 累加器在
  `justified_contain_in_space`（fspec.rs:4327）内，对 cur<0 的 piece（含
  address.cc:133 异空间 -1）只加 `vdata.size`，首个包含 piece 返回 res+cur
  —— 与 cc:252-261 逐语句对齐，piece 遍历 `.rev()` = cc:253 的
  `i=numPieces()-1..0`（least significant first，pieces MS-first 存储）。
- **排序/比较键**: 空间相等键三路齐全：join 逐 piece `vdata.space !=
  query_space → -1`（= address.cc:133）；plain `self.space != query_space →
  -1` 后委托 spaceless 数值体（alignment==0 路径=entry Address 的
  address.cc:133；alignment!=0 路径=cc:269 显式守卫，数值体 cc:270-282 与
  fspec.rs:4295-4307 对齐，含 wrap-around 拒绝与 left/right-justified 取模）。
  **调用方级无空间过滤，Ghidra 确实没有**。

### 1.2 `fillin_map_fallback`（src/fspec.rs:5968 ← fspec.cc:1638-1719）

- **删除自创守卫的正当性（本片核心）**: 旧代码 `t_active &&
  curentry.get_space() == t_space` 是 Ghidra 没有的调用方级过滤。Ghidra
  cc:1656 `curentry->justifiedContain(paramtrial.getAddress(),…)` 的 Address
  携带 trial 空间（fspec.hh:236 `addr` 为完整 Address），join entry 只能经
  fspec.cc:253 逐 piece walk 命中（join spaceid != register）。守卫使 join
  output entry 在 fallback 永不可达 → bestentry null → 全 trial markNoUse，
  与 Ghidra 相反。**删除正确且必需**。异空间拒绝现在只发生在 walk 内部，
  与 plain entry 行为等价——语义正确。
- **引用/输出参数**: `active` 原地突变序列逐行对齐：per-entry 评估
  set_entry/clear_entry（clear_entry = setEntry(null,0)，offset 归 0，与
  fspec.hh:242 一致）；null-best 分支**只 mark_no_use 不清 entry**
  （cc:1694-1697 的忠实细节，Rust 6046-6048 保持）；best 分支
  mark_used+set_entry / mark_no_use+clear；两处 sort_trials（cc:1668/1717）。
- **循环边界/遍历顺序**: 外层 entry 列表序；firstOnly 三条件
  （!isFirstInClass && isExclusion && getAllGroups().size()==1，cc:1649）——
  已核 `isExclusion()==(alignment==0)`（fspec.hh:134），fixture 的 e1
  (alignment 0, 无 first_storage, 单 group) 确实触发；offmatch walk 的
  break（offset 不等 / rem / indcreate）与 entry-null continue（k++ 不累计）
  边界、`offmatch < minSize → k=0`（cc:1684）全部对齐。
- **计数器/累加器**: offmatch 只在 `getOffset()==offmatch` 时累加；
  bestcover/bestclass 循环前重置一次、跨 entry 持久。
- **排序/比较键**: best 接受键 `(k==numTrials)&&(type<bestclass ||
  offmatch>bestcover)`（cc:1688）；Rust TypeClass 判别值与 type.hh:132-140
  逐一相等（General=0…Class4=103），初始 bestclass=Pointer=2 一致；
  sort_trials 经 `op_less`（fspec.rs:3354）与 cc:1896-1913 逐分支对齐
  （entry-null last → group → entry 同一（index 代指针，已文档化归一）→
  exclusion 比 offset / 非 exclusion 比地址（reverseStack 感知）→ size）。

### 1.3 fixture 依赖的地基（顺带核验）

`get_container`（fspec.rs:4362）join 路径（least-significant first、双端
overlap、res=piece）与 plain 路径（对齐 round-up）与 cc:295-328 对齐；
`ParamTrial` 全部 flag 谓词与 fspec.hh:243-264 位语义一致。

## 2. 双侧 fixture fspec_spaceless_rem_1204 — PASS（自洽核验）

- **真双侧**: C++ 侧以 class->struct hack 直接驱动锁定 oracle 的生产代码
  （真实 `Address(spc,off)` 携带空间、真实 `registerTrial`、真实
  `unjustifiedContainer`/`fillinMapFallback`）；Rust 侧逐 case 镜像（同
  spaces/offsets/sizes/minsizes/alignments/flags/trials；空间名字符串
  "ram"/"register"/"stack" 与 C++ `getName()` 一致，src/space.rs:222）。
- **31 行数学**: 1 envelope + 7 case 头 + 7+6+3+2+3+1+1 = 31 ✓（与
  observation_schema 声明一致）。
- **核心分歧行真实钉住修复**: uc stack 查询数值巧合 offset → 新代码 hit=0
  （旧 spaceless 会回写 register 容器）；uc reg:0x204 数值巧合高 piece 拒绝；
  fb_join（旧守卫 → bestentry null → 全 markNoUse vs 新 join best + 双
  trial used）；fb_cross_space_join 三空间 piece 匹配；firstOnly 跳过/放行
  对照对。metadata `covered_projection_status=MATCH`、双侧
  `ghidra_stdout_sha256 = rugra_stdout_sha256 = 485c2b85…` 在案。
- **runner 完整性**: pin-base schema2，锁定 oracle 四重身份（commit+tag+cpp
  tree+Makefile blob）+ 脏树检查 + 全 comparand sha256（含候选 fspec.rs
  overlay）+ 隔离快照双侧构建 + `diff -u` 字节比对 + 双侧 stdout pin。
  **现场核验: 当前 master 的
  src/fspec.rs=6f6e25c6…、docs/api/fspec.md=f0884bd5…、.cc=82e93e74…、
  .rs=eecc55e8…、runner=eee40027… 与 metadata pin 全部相等；
  `git diff 8d9aaf66..HEAD` 对 src/docs/tests/tools 零漂移**。
- **执行声明**: 31/31 byte-identical、fspec::tests 31/31、cargo check——按
  复核纪律未重跑（禁 cargo），以上为结构自洽 + pin 完整性核验；runner 的
  硬 hash 门使任何后续重跑自动复证。

## 3. phase0 重钉零漂移 — 声明核实成立

- `git show 8d9aaf66^:…metadata.json` 与 commit 后的
  `ghidra_stdout_sha256 = rugra_stdout_sha256 = 69c76294…` **逐字节相同**
  （commit 只改 4 个源 comparand pin：rust_fixture/fspec_rs/fspec_doc/
  crate_tree；stdout pin 未动）。
- fixture diff 恰为两处签名更新（`unjustified_container(spc,…)` +
  `assumed_extension(spc,…)`，后者补 55ef9943 的遗漏）；查询 tuple 本就携带
  spc，无语义引入。
- 语义上零漂移可信：phase0 uc/ae 的跨空间行（stack:0x2/8、ram:0x2008/8 等）
  与模型内异空间 entry 无数值包含关系（entry 布局 0x30+ / 0x2000+），新
  space-aware 结果与旧数值结果在这些行同为 oracle 值。
- 衍生 `FSPEC-PIN-STALE-0002`（possibleparam/findentry/endian_resolver pin
  滞后）已登记 P2 QUEUED（docs/TODO_BOARD.md:63），无未登记缺口。

## 4. A57（possibleparam）与本片语义一致性 — PASS

同一家族单一模式（A31→A46→A57→A65，WAVE_STATUS_2026-08-25_V3 §4）：

| 维度 | A57 `find_entry`/possibleparam（fspec.cc:660-680） | 本片 `unjustified_container`/fallback |
|---|---|---|
| 查询空间 | 显式 `space` 代 Address 携带 | 同（本次增补） |
| 空间拒绝位置 | walk 内部（cc:676 justifiedContain） | walk 内部（justified_contain_in_space） |
| join 可达性 | populateResolver 按 piece 空间注册（cc:1191+），`registered_extents` 镜像 | 逐 piece walk 匹配 |
| 调用方级过滤 | 无 | 无（本次删除自创守卫后归一） |

且**正确保留了 Ghidra 的函数间差异**：findEntry 走 resolver 窗口
（预过滤），unjustifiedContainer/fillinMapFallback 全列表扫描——Rugra 两侧
分毫不混。findResolve 意义上的查询空间解析（resolver 键 = 查询空间 index）
在 `registered_extents(e, space)` 与 `resolverMap[index]` 间等价（无注册即
None = 空 resolver）。家族内无互相矛盾的守卫残留；fspec 生产调用方
spaceless `justified_contain` 清零（现场 grep：仅 :4355 walk 内委托 + 测试）。

## 5. 发现 A（非阻塞，文档级）: fixture 行内注释/metadata expect 三处机制误标

行为不受影响（双侧同构、输出确定、hash 已钉），但注释归因错误：

1. case1 行 7 `reg 0x202/2` 注释称 "e2 container 0x200/8"——实际 e2
   minSize(4)>2 被门跳过 → **hit=0**（metadata expect 反而写对了："skipped
   for the min-4 e2 -> hit=0"；仅 .cc/.rs 行内注释错）。
2. case2 行 1 `reg 0x102/2` 注释称 "low piece just=2 -> PIECE 容器"——实际
   join minSize(4)>2 先跳过 → **hit=0**。低 piece just≠0 的 piece 容器行只在
   Rust 单测（该处 minsize=2）覆盖，**双侧 fixture 未覆盖**（双侧 piece 容器
   由 ram 高 piece 行 + just=0 早退行覆盖）。
3. case2 行 6 `stack 0x102/2` metadata expect 归因 "per-piece address.cc:133
   拒绝"——实际 minSize 门先跳过（结果同为 hit=0）。

处置建议：并入 FSPEC-PIN-STALE-0002 同批重钉时订正注释/expect 文字（改动
即触发 fixture hash 重钉，单独改不划算）；coverage 表述按本节收窄。

## 6. 发现 B（非阻塞，存量越界）: `get_container` join piece 选择的跨空间数值巧合窗

- Ghidra `Address::overlap` 对异空间返回 -1（address.cc:158）；Rugra
  `VarnodeData::get_addr()` 返回 spaceless Address（fspec.rs:3799），其
  `overlap`（address.rs:194）仅在双侧都有空间时才拒绝——spaceless 路径走
  数值臂。
- 后果：若 join 的**较低显著 piece 属异空间且数值区间包含查询**、真实包含
  piece 在更高显著位，Rugra `get_container` 会选错 piece（Ghidra 经
  address.cc:158 跳过）。本 commit 未触碰 `get_container`；fixture 未 staging
  该病态构型（需要跨空间同数值区间 piece）；FSPEC_GAPS_2026-08-23.md:169 对
  cc:295 记 M(U)。
- 处置建议：登记 P3 TODO（space-thread `get_container` 的 piece 选择，或复用
  `justified_contain_in_space` 已核过的查询空间守卫），与 ADDRESS-0001 家族
  归并跟踪。不阻塞本片。

## 7. 其他核验

- `// Ghidra:` 注解指向函数定义起始行（fspec.cc:1411/248/295/1638）正确；
  commit 散文行号有 3 处 off-by-one（minSize 门实为 cc:1416、just==0 实为
  cc:1419、best 键实为 cc:1688）——仅 prose，非机器检查目标，cosmetic。
- fspec.rs 不在机制 B/C 白名单；本片实际同时完成双侧差分（fixture）与独立
  复核（本报告），超出白名单要求。
- TODO_BOARD 本行状态 REVIEW 与本报告闭环；FSPEC-SPACELESS-REMAINDER 可翻
  DONE（残值 = §5/§6 建议项 + FSPEC-PIN-STALE-0002 批）。

## 8. 结论

四类决定性语义逐项核对通过；fixture 双侧自洽、pin 完整、零漂移声明与 git
证据一致；A57 家族语义归一。两项发现均为文档级/存量越界，不构成本片对齐
缺陷。

**Cross-Review: APPROVE**
