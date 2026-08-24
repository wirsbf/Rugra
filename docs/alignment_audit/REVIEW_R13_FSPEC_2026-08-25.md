# R13 独立复核报告 — FSPEC-JUSTIFIED-ENDIAN-0002 + RESOLVER-GATE-0003

- 复核对象: worktree `/home/wirs/.cache/rugra-wt-fspec-er` 分支 `agent/fspec-endian-resolver`
  - `d32a005` (align: thread space endianness through justified_contain_range + characterize_as_param resolver gate)
  - `b54b24b` (test: pin fspec_endian_resolver_1204 dual-side oracle fixture + re-pin justified_contain_1204)
- 复核者: 独立 Cross-Review Agent（机制 C）。自己读 Ghidra 原文，不采信实现者声明。
- Oracle: `ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`（锁定 12.0.4，已验证）。
- 复核方式: 只读 worktree/git；**双侧 oracle Ghidra 侧独立重跑**（`--ghidra-only`，不用 cargo，仅写 /tmp）；
  全部 63+63 行 oracle 值逐行手工推导比对。
- 结论: **Cross-Review: APPROVE**（范围=两 commit 的 write-set；发现 1 个租约外的预存 BUG 必须登记 + 若干非阻断建议）。

---

## 1. 必读 Ghidra 原文核实（逐字）

### 1.1 address.cc:131-141 `Address::justifiedContain` — 端序路由键 ✅

```cpp
int4 Address::justifiedContain(int4 sz,const Address &op2,int4 sz2,bool forceleft) const
{ if (base != op2.base) return -1;
  if (op2.offset < offset) return -1;
  uintb off1 = offset + (sz-1);
  uintb off2 = op2.offset + (sz2-1);
  if (off2 > off1) return -1;
  if (base->isBigEndian()&&(!forceleft)) {
    return (int4)(off1 - off2);
  }
  return (int4)(op2.offset - offset);
}
```

- **cc:138 分支键逐字确认 = `base->isBigEndian() && (!forceleft)`** — 端序来自地址所在
  SPACE 的 flag，`forceleft` 只是 BE 下的豁免开关。**修复的核心论断成立**：
  旧 Rust `if force_left {start} else {end}`（d32a005 diff 中删除的行）把
  `force_left=false` 无条件路由到 end 距离，即把 `!force_left` 当作 BE 路由 —
  LE 空间 + forceleft=false 时返回 end 距离，Ghidra 返回 start 距离。
- 新 Rust（src/fspec.rs:4560-4566）`if space_is_big_endian && !force_left { this_end - end_addr } else { addr - base }`
  与 cc:138-141 逐字对应；wrapping_add/sub 对应 uintb 回绕（cc:135-136）。
- cc:133 `base != op2.base` 空间守卫在 spaceless helper 中归属 caller（注释已声明，ADDRESS-0001 过渡）。

### 1.2 fspec.cc:682-719 `characterizeAsParam` — 两段扫描 + cc:708 门控 ✅

逐行确认结构：
- cc:685-690: `resolverMap[loc.getSpace()->getIndex()]` 按空间取 resolver；越界/空 → no_containment。
- cc:692: `iterpair = resolver->find(loc.getOffset())` — phase-1 窗口。
- cc:695-705 循环: `off = justifiedContain(loc,size)`; `off==0` 立即 return contains_justified
  （**早于该 entry 自身的 exclusion 检查**）; `off>0` → resContains; `isExclusion() && containedBy`
  → resContainedBy。两个 bool 只在 phase-1 置位，无重置。
- cc:706-707: 分档梯子 resContains → contains_unjustified; resContainedBy → contained_by。
- **cc:708 门控**: `if (iterpair.first != resolver->end())` — 此时 iterpair.first 已走完
  phase-1 窗口（== iterpair.second），条件语义 = "find 窗口终点不是 map 终点"。
- cc:709: `iterpair.second = resolver->find_end(loc.getOffset() + (size-1))` — phase-2 扫描上界
  （uintb 回绕加法）。
- cc:710-716: 只查 `isExclusion() && containedBy` → return contained_by。

### 1.3 rangemap.hh（find/find_end/insert/unzip/zip）— 门控键的数学核实 ⚠️（结论: 等价成立，论证措辞不精确）

- 多重集按 `(last, subsort=position)` 排序（rangemap.hh:88-91）；细化子区间互斥不重叠，
  同一 record 在其覆盖的每个子区间重复出现；find(point)（:332-347）返回包含 point 的那个
  子区间的全部重复条目 = "extent 数值包含 point 的所有 record"。
- find_end(point)（:389-404）= 包含 point 的子区间之后第一个子区间（无包含者则为第一个
  last > point 的子区间）。
- **实现者的论证**："细化区间在每个注册起点分裂, 故上方存在区间 iff 存在更高起点"。
- **复核结论: 该 iff 作为 rangemap 字面命题为假**。反例：extents [0,15]+[8,31]，query
  start=8 — 细化边界 15|16 来自 E1 的**终点**（unzip/zip 也按终点分裂，rangemap.hh:177-215），
  无任何起点 > 8，但 phase-1 窗口（[8,15] 子区间）终点 ≠ map end → Ghidra 门是开的。
- **但行为（返回值）等价成立，复核者独立证明**：
  1. phase-2 相对 phase-1 的"新 record"= 有子区间在窗口上方且不覆盖 query start 的 record
     ⟺ extent start > query start（覆盖 start 的已在 phase-1 被查；整体在下方的不会出现在
     phase-2）。新 record 的 justifiedContain 恒为 -1（query start < entry base → cc:134/271
     每条路径 -1，join 逐 piece 同理），只能经 exclusion+containedBy 产生新信息。
  2. 门开而无更高起点时（如上反例），phase-2 只会**重访** phase-1 已查过的 record，谓词
     (isExclusion && containedBy(loc,size)) 与 cc:702 完全相同 — 若为真，phase-1 已置
     resContainedBy 并在 cc:707 提前返回，phase-2 不可能产生不同结果。
  3. 反向：∃ 起点更高 ⟹ 该 record 首子区间 first = 其起点 > query start ⟹ 在窗口上方 ⟹
     Ghidra 门必开。
  ∴ Rust 门（∃ 注册 extent start > query start）恰在 Ghidra phase-2 能产生新信息时打开，
  窗口 (offset, query_end] 与 Ghidra 扫描 [窗口终点, find_end(query_end)) 对新 record 的
  覆盖一致（start > query_end 的 record 双方都不扫，且其 containedBy 的 cc:206 上界检查
  必假）。**等价性成立**——但成立理由是结果等价，不是字面 iff（见建议 C）。

### 1.4 fspec.cc:248-283 `ParamEntry::justifiedContain` + cc:199-207 `containedBy` ✅

- cc:251-262 join walk: 从最不显著 piece 起倒序，`vdata.getAddr().justifiedContain(vdata.size,
  addr,sz,false)` — forceleft 恒 false，端序取**逐 piece 自己的 space**（cc:255）。
  Rust fspec.rs:4277-4280 逐字对应（`vdata.space.is_big_endian()`）。
- cc:264-267 alignment==0: `Address entry(spaceid,addressbase); entry.justifiedContain(size,addr,sz,
  (flags&force_left_justify))` — forceleft 取 entry 自身 flag，端序取 entry space。
  Rust fspec.rs:4289-4293 对应（`FORCE_LEFT_JUSTIFY` flag + `self.space.is_big_endian()`）。
- cc:202: `if (spaceid != addr.getSpace()) return false;` — join entry 的 spaceid = join 空间，
  永不等于查询空间 → join entry 的 containedBy 结构性为 false。populateResolver（cc:1191-1216，
  逐行核实: 普通 entry 注册自身 [base, base+size-1] 到自己的 space；join 逐 piece 注册到
  piece 的 space，position 逐 piece 递增）。Rust `e.space == space` 守卫
  （fspec.rs:4952/4976）+ `registered_extents` 的 piece 过滤复刻此结构 — 对普通 entry 恒真
  （注册必在自己的 space），对 join entry 复刻 cc:202 的 false。✅

### 1.5 heritage.cc:1221 `guardCallOverlappingInput` truncate 调用 ✅

```cpp
int4 truncateAmount = addr.justifiedContain(size, truncAddr, vData.size, false);
```

- forceleft 恒 false，端序来自 `addr` 的 heritage 空间。Rust heritage.rs:2779-2786 传
  `space.is_big_endian()`（`space` 即本次 heritage 的空间，与 addr 同源）✅。
- **"LE 下 SUBPIECE 常量 = start 距离" 论断核实**: p-code SUBPIECE(v, c) 输出 =
  v 右移 8c 字节后截到输出尺寸。LE 空间低地址 = 最低有效字节 → 截掉 c 个 LSB =
  c × start 距离；BE 空间 LSB 在最高地址 → c = end 距离。oracle tr 行
  （le 4/be 8, le 0/be 8, le 6/be 0, le 2/be 2, -1/-1）与手工推导全部一致。
- **Ghidra heritage 侧共有 4 个 justifiedContain 调用点**（1221/1336/1358/1420）+
  funcdata_varnode.cc:512（adjustInputVarnodes）。Rugra 现状:
  | Ghidra | Rugra | 状态 |
  |---|---|---|
  | cc:1221 | heritage.rs:2779（本 commit 修复，helper 6 参） | ✅ 对齐 |
  | cc:1336 | heritage.rs:3356 **硬编码 0** | LE 值恰为 0（正确-under-LE）；BE 应为 size−sizeFront — 预存 |
  | cc:1358 | heritage.rs:3385 **硬编码 0** | **BUG：LE 真值 = sizeFront+retSize ≠ 0**（见发现 A）— 预存 |
  | cc:1420 | 未移植（try_output_stack_guard 保守 false，已注释声明） | 预存已声明 |
  | funcdata_varnode.cc:512 | funcdata.rs:8554 硬编码 start 距离（已声明 RUGRA-GAP） | 预存已声明 |

### 1.6 fspec.cc:5068-5089 `transferLockedOutputParam` — 传 false 的合理性 ✅

cc:5073/5075/5082/5084 仅观测 `>= 0`。两个距离分支在"含住"时均非负（卫语句保证
op2.offset ≥ offset 且 off2 ≤ off1），-1 只来自与端序无关的两个卫语句 —
**符号与端序参数无关**，传 `false`（LE 过渡默认）观测等价。✅

---

## 2. 逐项复核清单结论

### 2.1 四类语义核对

| 语义类 | address.cc:131 / justified_contain_range | fspec.cc:682 / characterize_as_param |
|---|---|---|
| 引用/输出参数 | 纯函数，返回 i32，无突变 ✅ | `&self` 只读，返回分类码，无突变 ✅ |
| 循环边界/遍历顺序 | 无循环；两独立卫语句逐字（cc:134/137）✅ | phase-1 = extent 含 query start（= find 窗口）；Rust 按 entry 列表序、Ghidra 按 (last,position) 序 — **结果序无关**（==0 支配、bool 累加器），且 off==0 ⟹ 含住 ⟹ 必在窗口内，无序致分歧 ✅ |
| 计数器/累加器 | 无（off1/off2 回绕加法一致）✅ | resContains/resContainedBy 仅 phase-1 置位无重置 ✅ |
| 排序/比较键 | **端序路由键 = space && !force_left ✅（核心）** | **resolver 门控键 = ∃ 注册起点 > query start：字面 iff 为假但结果等价（§1.3 独立证明）✅**；分档梯子 ==0 → >0 → containedBy → none ✅ |

### 2.2 characterize_as_param 窗口化对照 ✅
phase-1 membership = `registered_extents` 任一 extent 含 offset（含 join 逐 piece）=
find(loc.getOffset()) 窗口；phase-2 门 + (offset, query_end] 窗口 = cc:708-716（§1.3 等价）；
`query_end = offset.wrapping_add(size).wrapping_sub(1)` = cc:709 uintb 语义（负 size 的
符号扩展行为两侧一致）；join 的 `e.space == space` 守卫 = cc:202（§1.4）。

### 2.3 heritage truncate 端序传参 ✅（本 commit 触点）
cc:1221 触点正确（§1.5）。其余触点见发现 A/B（预存、租约外）。

### 2.4 双侧 fixture ✅（复核者独立重跑 + 全行手工推导）
- **fspec_endian_resolver_1204**: 复核者以 `--ghidra-only` 从锁定 oracle tree 重建
  libdecomp.a 并重跑 C++ 侧：`GHIDRA_LOCKED_OUTPUT_OK ... stdout_sha256=2d59318a7485...`
  与 metadata `ghidra_stdout_sha256`、commit message 声明**逐字节一致** — metadata 是真
  oracle 输出而非手写。63 行（1 envelope + 4 case 头 + 28 jc + 8 pe + 10 tr + 12 ch）全部
  手工推导一致，抽查（远超 3 行）示例：
  - `jc base=0x1000 esz=8 qoff=0x1000 qsz=4 fl=0 be=0 off=0`（ENDIAN-0002 决定性行:
    LE+forceleft=0 = start 距离 0；旧代码会输出 4）
  - `tr spc=be addr=0x1000 size=16 toff=0x1004 tsz=4 amt=8`（off1−off2 = 0x100F−0x1007）
  - `ch qoff=0x150 qsz=256 cls=3`（start 在两 extent 之间、区间盖住 E2 → 门开、phase-2
    扫到 E2 exclusion containedBy → 3）；`ch qoff=0x300 qsz=8 cls=0`（高于全部 extent →
    门关）；`ch qoff=0x204 qsz=8 cls=0`（extent 内 poke 高 → 含不住且无更高起点 → 门关）
  - C++ harness 内建 LE(false)==LE(true)==BE(true) 一致性自检（.cc:175-179）额外加固。
- **Rugra 侧**: 禁 cargo 未重跑；但（i）Rust fixture 逐 case 镜像 C++（同一 GEOMS/TRGEOMS/CHC
  表，同一打印格式）；（ii）复核者对库函数逐行手推全部 12 ch 行 + 抽样 jc/pe/tr 行与新路由
  一致；（iii）runner（结构核实：pin-base schema2、base=d32a005、overlay=src/fspec.rs、
  9 项 comparand 哈希 + host + registry lock 闭包全验证、owned-files 前后不变、byte-diff
  必须为空才 OK）在 b54b24b 声明真实双跑 OK。metadata `rugra_stdout_sha256 == ghidra_stdout_sha256`。
- **静态哈希自洽**: worktree HEAD 的 src/fspec.rs、两个 fixture、runner、docs/api/fspec.md
  的 sha256 与 metadata comparand 逐项相等（复核者计算）。b54b24b 未触碰 src/docs
  （`git diff d32a005 b54b24b --stat -- src/ docs/` 为空）。
- **justified_contain_1204 重钉**: `--ghidra-only` 独立重跑复现 `6526dab3...`（与
  metadata/commit 声明一致）。cpp_fixture_sha256 **不变**（重钉诚实地只改 Rust 侧:
  view=start 从 `(…,true)` 改 `(…,false,false)` — 真实缺陷路由；view=end `(…,false,true)`；
  pe be=1 行因枚举空间无法 stage BE entry 改为 helper 直调并明确标注 ADDRESS-0001 helper 级
  钉住而非 wrapper 级）；overlay 表新增 src/heritage.rs（5→6 参触点，快照可编译的前提）；
  两个旧 residual 标 RESOLVED-BY-SUCCESSOR 指向后继 fixture，账目诚实。

### 2.5 两个新缺口事实核实 ✅
- **FINDENTRY-GATE-0005 属实**: Rust find_entry（fspec.rs:4896-4911）确为线性扫描
  （`for (i, e) in self.entry`）+ plain-space 过滤（`e.get_space() != spc → continue`），
  join entry 永不被 piece-windowed（Ghidra 的 resolver 含 join 逐 piece 注册、findEntry 可
  返回 join entry）。另核实: Rust 扫描**完全没有** Ghidra 的 find-窗口限制 — just=false 时
  extent 不含 query start 的 entry 也会被返回（Ghidra 返回 NULL），且多 entry 命中时
  "第一个"的选取序（列表序 vs (last,position) 序）也可能不同。residual 措辞"需要与
  characterize_as_param 相同的 resolver-window 处理"覆盖了这几点。属实。
- **JOIN-WINDOW-0004 属实**: registered_extents 的 piece 窗口结构性在但无 join fixture
  覆盖（两个 fixture 均未 stage join entry）。属实。
- **登记状态**: 主仓 docs/TODO_BOARD.md:49/51（2026-08-25）已登记 0001 及
  0002+0003（REVIEW, 候选即本两 commit, "R13 复核中"）并预告 0004/0005"待 R13 核实后排期"。
  worktree 内 board 早于分支点属正常（board 由主 agent 维护）。登记流程合规。

---

## 3. 发现（按严重度）

### 发现 A —【BUG，预存，租约外，须立即登记 TODO】guard_output_overlap_stack 后件 SUBPIECE 常量错值
- 位置: `/home/wirs/.cache/rugra-wt-fspec-er/src/heritage.rs:3385`（`fd.new_constant(4, 0u64)`）。
- Ghidra heritage.cc:1358: `addr.justifiedContain(size, addrBack, sizeBack, false)`，
  addrBack = retAddr+retSize = addr+sizeFront+retSize。
  - **LE 真值 = sizeFront + retSize**（start 距离），BE 真值 = size − sizeFront − sizeBack − …
    经复核 = 0（end 距离 (addr+size−1)−(addrBack+sizeBack−1)）。
  - 硬编码 0 是**前件（cc:1336）的 LE 值**，被错误复制到后件。即使当前全 LE 过渡模型下也错
    （除非 sizeFront+retSize==0，该分支不可达）：SUBPIECE(whole, 0) 取的是前段字节而非后段。
  - 前件 heritage.rs:3356 硬编码 0 = cc:1336 的 LE 正确值（BE 应 size−sizeFront）。
- 非本两 commit 引入（d32a005 只动 2772-2786），不阻断本次复核，但**必须登记 TODO 并修复**
  （修正方向: 两处改调 `justified_contain_range(addr, size, <op2>, <sz>, false,
  AddressSpace::Stack.is_big_endian())`，即 cc:1336 传 addr/sizeFront、cc:1358 传
  addrBack/sizeBack）。
- 同族: funcdata.rs:8554 `sa = vn_addr - addr`（cc:512 LE 语义硬编码，已有 RUGRA-GAP 声明）；
  cc:1420 触点未移植（try_output_stack_guard 已声明保守 false）。

### 发现 B — join walk 缺 per-piece 空间失配 -1（预存，ADDRESS-0001/0004 伞下）
- Ghidra join walk 对不在查询空间的 piece 经 cc:133（base != op2.base）恒 -1 → res += size。
  Rust join walk（fspec.rs:4277）对每个 piece 做**纯数值**判定 — 跨空间 join（如寄存器+栈）
  被查询时，异空间 piece 的数值恰好嵌套时会误返回 ≥0。本 commit 只加了端序参数，未改此
  行为（预存）；须在 JOIN-WINDOW-0004 的 join fixture 中一并钉住/修复。

### 建议 C — 门控等价性的措辞修正（文档精度，非阻断）
- commit message、fspec.rs:4958-4962 注释、metadata decisive_semantics 三处均用
  "上方存在区间 iff 存在更高起点"这一**字面为假**的引理（细化也按终点分裂，rangemap.hh
  unzip/zip）。正确的论证是§1.3 的结果等价（多余上子区间只会重访 phase-1 已查 record）。
  建议后续 commit 修正措辞，防止未来读者把假引理当 rangemap 事实复用。

### 建议 D — fixture 注释笔误（纯注释）
- fspec_endian_resolver_1204.cc:131 注释 "size-1 high byte: start 3, end 0" — 实际 end 距离
  = 0x1007−0x1003 = **4**（oracle 行输出 4）。值来自真 oracle 不受影响，仅注释错。

### 建议 E — `e.space == space` 守卫对未来 join 模型的约束
- 该守卫复刻 cc:202 的前提是 join entry 的 `e.space` 永不为查询空间。当前枚举模型 join 未
  stage；将来 join-space manager 落地时必须保证 join entry 的 space 字段 ≠ 任何查询空间，
  并由 JOIN-WINDOW-0004 fixture 钉住（否则 contained_by 路径会用 join 空间 offset 做
  cc:203-206 数值比较而 Ghidra 恒 false）。

---

## 4. 四类决定性语义核对清单（复核者独立版）

| 函数 | 引用参数 | 遍历顺序 | 计数器 | 排序/比较键 |
|---|---|---|---|---|
| justified_contain_range ↔ address.cc:131 | [x] 纯函数 | [x] 卫语句逐字 | [x] 回绕加法 | [x] **space_be && !force_left** |
| characterize_as_param ↔ fspec.cc:682 | [x] &self 只读 | [x] 窗口等价(§1.3)+结果序无关 | [x] 两 bool 仅 phase-1 | [x] 门控结果等价+梯子序 |
| ParamEntry::justified_contain ↔ fspec.cc:248 | [x] | [x] join 倒序 piece | [x] res 累加 | [x] 逐 piece/entry space 端序 |
| guard_call_overlapping_input truncate ↔ heritage.cc:1221 | [x] | [x] 无循环 | [x] | [x] heritage space 端序+forceleft=false |

## 5. 判定

- 两 commit 范围内（src/fspec.rs 端序穿线 + resolver 门控、src/heritage.rs:2779 触点、
  docs 同 commit 同步、双侧 fixture + 重钉）**全部核实对齐**，oracle 侧独立重跑复现。
- 发现 A 为租约外预存 BUG（heritage.rs:3385），不阻断本合并，但须主 agent 立即登记 TODO
  （同 wave 内修复，属 ENDIAN-0002 同族 SUBPIECE 常量正确性）。
- **Cross-Review: APPROVE**
