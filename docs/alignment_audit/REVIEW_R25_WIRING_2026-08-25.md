# R25 — Cross-Review: OPTIONS-SPLITDATATYPE-WIRING-0002 (toggleAction + allacts wiring)

- 复核对象: `eacaeade`(agent/options-wiring-v2) → `b5a554d9`(master 集成版)
- 复核 Agent: R25 (独立复核, 只读主仓)
- 日期: 2026-08-25
- Oracle: ghidra HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b` (Ghidra_12.0.4_build) — 复核时实测一致
- 结论: **Cross-Review: APPROVE** (3 条 minor findings, 均不阻塞, 见 §6)

两 commit 的本单元文件 (src/action.rs, src/arch.rs, fixture 三件套, runner, docs/api/{action,arch}.md)
经 `git diff eacaeade b5a554d9 -- <files>` 验证**完全一致**; 两分支间差异仅为 TODO_BOARD 其他
wave 条目的集成期状态行, 不属于本单元。

## 1. 复核方法

按机制 C, 不采信实现 Agent 的 Alignment Evidence 块, 独立打开 Ghidra 逐行读完全部被引用函数体:

| Ghidra 函数 | 行号(实测) | 状态 |
|---|---|---|
| `ActionDatabase::toggleAction` | action.cc:1036-1053 | 全文已读 |
| `ActionDatabase::addToGroup` | action.cc:1090-1096 | 全文已读 |
| `ActionDatabase::removeFromGroup` | action.cc:1103-1109 | 全文已读 |
| `ActionDatabase::registerAction` | action.cc:1126-1138 | 全文已读 (delete+replace 语义) |
| `ActionDatabase::getAction` | action.cc:1112-1120 | 全文已读 (throw 文本) |
| `ActionDatabase::getGroup` | action.cc:1006-1015 | 全文已读 (throw 文本) |
| `ActionDatabase::resetDefaults` | action.cc:986-1004 | 全文已读 |
| `Architecture::buildAction` | architecture.cc:585-591 | 全文已读 |
| `Architecture::resetDefaults` | architecture.cc:1438-1445 | 全文已读 (1442 = allacts arm) |
| `OptionSplitDatatypes::apply` | options.cc:999-1019 | 全文已读 |
| `OptionSplitDatatypes::getOptionBit` | options.cc:982-990 | 全文已读 |
| `ActionDatabase::universalAction` | coreaction.cc:5462-… | 全文已读 (glb 仅用于 ActionExtraPopSetup 的 stackspace) |

另核对 action.hh:31-40 (ActionGroupList = `set<string>`)、action.hh:298-324 (ActionDatabase 成员)、
architecture.hh:212 (`ActionDatabase allacts;` by-value — 引用精确)。

## 2. 清单项 1 — 四类语义核对 (toggleAction)

语句序逐句对照 (Ghidra action.cc ↔ Rugra src/action.rs:2066-2098):

| # | Ghidra | Rugra | 判定 |
|---|---|---|---|
| 1 | :1039 `getAction(universalname)` (throw "No registered action: universal", groupmap 未动) | :2070 `action_index("universal")` + panic 同文本, 在任何组变异之前 | OK |
| 2 | :1040-1043 `addToGroup`/`removeFromGroup` | :2074-2078 `add_to_group`/`remove_from_group` | OK |
| 3 | :1044 `getGroup(grp)` (throw "Action group does not exist: "+grp) | :2080 `get_group` + panic 同文本; 经 groupmap_entry 缺省插入后必成功, 与 Ghidra `groupmap[grp]` 后 getGroup 必成功同构 | OK |
| 4 | :1045 `act->clone(curgrp)` — 源恒为 **universal** (非旧 root) | :2086 `actionmap[universal_idx].…clone_for_groups(&curgrp)` | OK |
| 5 | :1047 `registerAction(grp,newact)` — delete 旧 + 原位替换 | :2093 `register_action_named` — 原位替换 = drop 旧对象 | OK |
| 6 | :1049-1050 `if (grp == currentactname) currentact = newact;` | :2095-2096 `if grp == self.currentactname { self.currentact = self.action_index(grp); }` | OK |

- 引用/输出参数: `(&mut self, &str, &str, bool)` ↔ `(const string&, const string&, bool)`。Ghidra 返回
  新 root 指针, Rust 返回 `()` 由调用方经 `get_action`/`get_current` 重取 — register 后 grp 名下即新
  对象, 可观察状态等价 (commit message 已声明该差异)。
- currentact 更新条件: 同一字符串相等比较; Rust 以索引代替指针, `register_action_named` 原位替换
  (或尾部 push) 后重取 `action_index(grp)` 恒指向新对象, 且规避了 Ghidra 在 `grp=="universal"` 边界
  下 `act` 悬垂 (Ghidra 侧不再解引用故无 UB, Rust 侧索引替换天然安全) — 行为等价。
- 计数器/累加器: 无计数器; `isDefaultGroups=false` 在 add/remove **首句** (cc:1093/1106 ↔
  rs:2031/2042), 位置一致。
- 排序/比较键: `BTreeSet<String>` ≡ `std::set<string>` (同一字典序); addToGroup 返回
  `insert().second` ↔ `BTreeSet::insert` bool; removeFromGroup 返回 `erase()>0` ↔ `BTreeSet::remove` bool。
- groupmap 缺省插入: `groupmap_entry` (rs:2048-2057) ≡ `map::operator[]` (cc:1094/1107)。

build_action (arch.rs) ↔ buildAction (cc:585-591): `universal_action()` + `reset_defaults()` 两调用序
一致; `parseExtraRules(store)` 缺失已登记 **ARCH-PARSEEXTRARULES-0001** (TODO_BOARD:76, P2), 注释
说明"输入路径存在前不可观察"属实 (extra rules 追加发生在 universal 树构建前, 无 spec 输入即无差异)。
reset_defaults 的 allacts arm ↔ cc:1442, `None` 跳过有注释 (Ghidra by-value 无法表达 None 状态;
pre-build_action 期调用 resetDefaults 在 Ghidra 侧同样不可能发生 — 构造期 allacts 空库时
Ghidra `setCurrent("decompile")` 会经 deriveAction throw, Rugra 行为同类)。

`universalAction(glb)` 的 glb 参数实测仅传给 `ActionExtraPopSetup("base",stackspace)` (coreaction.cc
域内), 属运行期消费者; Rugra 既有 `universal_action()` 不带 conf 是**本 commit 之前**的既有结构,
不在本单元 write-set, fixture 不经 build_action 故不受影响。

## 3. 清单项 2 — ActionGroupList 键 String 化影响面

影响面闭合:
- `from_members(&[&'static str])` 签名不变, 内部 `to_string`; 调用方 (set_group rs:1922 /
  groupmap_entry rs:2053 / action.rs:2284) 零改动。
- `contains(&str)` 经 `Borrow<str>` 与 `child_groups`/`rule_groups` (`Vec<String>`, rs:637/1179) 兼容。
- `ActionGroupList` 使用面全仓仅 src/action.rs 与 src/options.rs (后者仅注释提及)。
- 运行时组名 (toggle 的 `grp`) 需要 `String` — Ghidra `set<string>` 本就是值语义, String 化是
  正确的 Rust 对应, 非"替代实现"。

## 4. 清单项 3 — 双侧 fixture 25/6 自洽

- **25 records** = init state + 8 cases × (apply+state+identity) = 1+24; runner `wc -l` 与
  `expected_stdout_sha256 = 8662fd98…` 双重锁定 (与 commit message 一致)。
- **6** = metadata `coverage` 恰 6 维度 (reclone/group membership/tree/error paths/forwarding pair/
  arch embedding), 全部 MATCH + 逐条说明。
- oracle 侧 (options_wiring_1204.cc): `#define private public` 可见性 hack 只做状态观察, 生产体
  链接自锁定 libdecomp.a (git archive 锁定 commit 重建); `option.apply(&arch,…)` 是**真实生产**
  OptionSplitDatatypes::apply → 真实 toggleAction 链。TestArch 仅 stub 选项路径不会调用的纯虚函数。
- comparand (options_wiring_1204.rs): 驱动生产 `options::OptionSplitDatatypes::apply` +
  生产 `split_action_toggles` + 两次生产 `toggle_action`; 转发序 (先 splitcopy 后 splitpointer,
  grp=getCurrentName()) 与 cc:1008-1015 一致 (toggleAction 不改 currentactname, 取一次复用与
  Ghidra 每次重取等价)。无手写 expected。
- identity 通道: 双侧均以 flags 字段/ordinal 存构造序数 (从 100 起, 单调递增), 规避分配器地址
  复用 — 两侧对称, 且 fixture 声明"identity 仅经序数观察, 不用原始地址"。
- metadata 完整性 (本复核实测): oracle 五重身份 (HEAD/tag/cpp tree/makefile blob/Rugra base tree)、
  7 个 comparand sha256 + input_fingerprint 重算、host 工具链指纹 — **与当前 master 工作区文件
  零漂移** (全部 OK)。
- runner (run_options_wiring_oracle.sh): env -i 清洗、不可变 fd 自校验、owned 文件 before/after
  drift 检查、强制 `overall_status == "MISMATCH"` (禁止 fixture 自称整体 MATCH)、双侧 `cmp` 逐字节。
- p1/p2 错误序核对: Ghidra cc:1003 赋值前 throw (零突变) ↔ options.rs apply `get_option_bit(p1)`
  Err 即返回 (config 未动); cc:1004 部分赋值后 throw ↔ options.rs 先 `arch.split_datatype_config =
  new_config` 再返回 Err — 等价。此为 cc:1002-1019 的逐行移植, 本 commit 未改其体, fixture 复用。

## 5. 清单项 4 — Send+Sync supertrait 必要性 (RUGRA-GLUE 声明验证)

声明成立:
- `Architecture` 存在被 `Arc` 共享的真实消费者: src/grammar.rs:1296 `pub glb: Option<Arc<Architecture>>`
  (new_with_arch 构造), 另有多处 `thread::spawn` (src/bin/rugra.rs:255、heritage.rs:6455、
  examples)。跨线程共享 ⇒ Architecture 需 Send+Sync。
- 本 commit 给 Architecture 增设 `allacts: Option<Arc<RwLock<ActionDatabase>>>` (grammar.rs 的
  parser 在 Arc<Architecture> 内持有它), ActionDatabase 持 `Vec<Box<dyn Action>>` 与
  `Arc<dyn Fn() -> Box<dyn Action>>` factory — `dyn Action`/`dyn Rule`/`dyn Fn` 不带
  Send+Sync supertrait 则整链不自动 Send+Sync。supertrait 是必要的最小 glue。
- 无作弊: 全仓 `unsafe impl Send/Sync` 仅 4 处 (prefersplit.rs:137 / sleigh_ffi.rs:242 /
  transform.rs:668 / subflow.rs:264), 均为其他类型的既有代码, 不涉及 Action/Rule。
- RUGRA-GLUE 注释如实声明理由; `ActionFactory`/`RuleFactory` 与两个 `add_*_factory_in_group`
  bound 同步加宽, 逻辑闭合。

## 6. Minor findings (不阻塞, 建议随 0003 或最近的相关 commit 修正)

- **M-1 (注解行号)**: `src/arch.rs` `build_action` 的注解 `// Ghidra: architecture.cc:582
  Architecture::buildAction` — 582 是 doc 注释首行, 函数**定义**起始行是 **585**
  (AGENTS 铁律 1.3/机制 D 要求指向定义行)。本单元其余注解 (action.cc:1036/1090/1103/1006/1112/
  1126/1145/986/1021, coreaction.cc:5462, architecture.cc:1438, architecture.hh:212) 经实测全部
  精确。582 存在故 check_ghidra_refs 不拦。
- **M-2 (注释陈旧)**: `src/options.rs` `split_action_toggles` 的 RUGRA-GLUE 块及 `apply` 内
  转发注释仍写 "Architecture does not (yet) own an allacts field" — 本 commit 落地 allacts 后
  文字已过时 (实际工作是 0003 的直调转发, 已登记 TODO_BOARD:75)。文字性陈旧, 无行为影响。
- **M-3 (表述张力)**: commit message "Runner: B2 MATCH" 指 covered projection (runner 输出行同
  此措辞); metadata 顶层 `overall_status: "MISMATCH"` 是更保守的聚合 (0003 未接线 +
  build_action UNTESTED)。做法方向正确 (runner 甚至强制 overall 必须 MISMATCH), 但后续读者应以
  metadata 为准 — 建议未来 commit message 措辞用 "covered projection MATCH" 消歧。

## 7. 判定

- 机制 B 白名单: action.rs/arch.rs 均不在 {printc,prettyprint,varmap,blockaction,coreaction,ruleaction},
  Differential 块已声明; E2E curl 未跑的理由 (allacts 无生产消费者, 0003 后随 wave 门禁补跑) 成立。
- 机制 C: 本单元是主管线 Action 基础设施, TODO_BOARD:74 已登记 "机制 C Cross-Review 待做" —
  本报告即补该环节。集成流程 (先集成后补独立复核) 与项目惯例一致。
- 残留登记完备: OPTIONS-SPLITDATATYPE-WIRING-0003 / ARCH-PARSEEXTRARULES-0001 /
  FUNCDATA-TESTS-FLAKY-0001 (pre-existing, 纯净 base 13/21/25 证据) 均在 TODO_BOARD 且 write-set
  明确。
- 四类决定性语义逐项核对通过; fixture 双侧自洽且与当前 master 零漂移; Send+Sync glue 必要性
  经真实消费者证实。

## Cross-Review: APPROVE

(附 M-1/M-2/M-3 三条 minor findings, 均为文字/注解层面, 不构成行为 MISMATCH; 建议主 Agent 在
更新 TODO_BOARD:74 状态时引用本报告, 并将 M-1 纳入 0003 write-set 或单独 docs-fix。)
