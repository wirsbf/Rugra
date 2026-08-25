# Cross-Review R23 — VARMAP-GATHEROPEN-GUARD-0001 (commit dc6f0bfa)

- Reviewer: 独立复核 Agent（机制 C），只读主仓，未改仓库、未跑 cargo
- 复核对象: `dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6`（master HEAD）
- Oracle 核实: `ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b` (tag Ghidra_12.0.4_build) ✓
- 复核方法: 逐行打开 Ghidra varmap.cc/heritage.hh/database.cc/database.hh/rangemap.hh/fspec.cc/type.cc/type.hh/varnode.cc，
  独立列四类语义清单后比对 src/varmap.rs；不采信实现 agent 的 Evidence 声明
- 日期: 2026-08-25

## 判定

# Cross-Review: APPROVE

（附 2 项 REQUIRED-FOLLOWUP，均非本 commit 引入或当前不可观察，不构成本四件套的 MISMATCH；
详见 §5。）

## 1. 四类语义逐函数核对

### 1.1 MapState::addGuard — Ghidra varmap.cc:1003-1039 vs src/varmap.rs:1777 add_guard

| 语义类 | Ghidra | Rugra | 判定 |
|---|---|---|---|
| 引用/输出参数 | guard const 只读；typeFactory 用于 getBase(step,TYPE_UNKNOWN)；addRange 突变 maplist | guard 只读借用；make_int_type(types,step)；add_range 突变 self | ✓（make_int_type 实现为 `get_base(size, TypeMetatype::Unknown)`，src/varmap.rs:1002-1011，与 :1031 等价；命名误导但行为正确） |
| isValid 门 | `!op->isDead() && op->code()==opc`（heritage.hh:169 逐字核实） | get_op() Some + `!is_dead()` + `opcode != opc` 双条件（:1784-1791） | ✓（Weak upgrade 失败对应 op 已销毁，是 isDead 的强化形式） |
| step 门 | `step==0` return（:1008） | `guard.step == 0` return（:1794） | ✓ |
| 地址类型下钻 | `getIn(1)->getTypeReadFacing(op)`；TYPE_PTR 解一层 ptrTo + `while TYPE_ARRAY` 全层（:1009-1014） | inrefs[1] 类型；Pointer→ptr_to + `while Array` 全层（:1799-1818） | ✓ 结构；⚠ read-facing 差异见 §5.1 |
| outSize | STORE=getIn(2)->getSize()，LOAD=getOut()->getSize()（:1015-1019） | 同分支同 slot（:1821-1831） | ✓ |
| 整除改写 | `outSize!=step` 时 `outSize>step || step%outSize!=0` 拒，否则 step=outSize（:1020-1027） | 同一条件序与改写（:1834-1842） | ✓ |
| 对齐重定型 | `getAlignSize()!=step` 时 `step>8` 拒，否则 getBase(step,TYPE_UNKNOWN)（:1028-1032） | `get_align_size()!=step` → `step>8` 拒 / make_int_type（:1846-1851） | ✓ |
| minItems 公式 | isRangeLocked(analysisState==2, heritage.hh:168): `((max-min)+1)/step`（uintb 回绕）后 -1；else 3（:1033-1038） | `analysis_state==2`: `span= wrapping(max-min)+1`; `(span/step) as i32 - 1`; else 3（:1855-1864） | ✓（uintb 无符号回绕 ↔ u64 wrapping；除法后 as i32 截断点与 Ghidra uintb→int4 赋值截断相同） |
| addRange 参数 | (min, ct, 0, open, minItems-1) / (min, ct, 0, open, 3) | (get_minimum(), Some(ct), 0, Open, min_items) | ✓ |

### 1.2 MapState::gatherSymbols — varmap.cc:1044-1059 vs src/varmap.rs:1877 gather_symbols

- 遍历序（本项最大风险点，已深挖）: Ghidra `rangemap->begin_list()` 返回
  `std::list<SymbolEntry> record`（rangemap.hh:66-137，EntryMap=rangemap<SymbolEntry>，
  database.hh:164）——**纯插入序链表，非树序**。Rugra `materialize_maptable`（:2628-2636）
  按 mapentry_log 插入序 replay 进 RangeMap，`records()`（src/rangemap.rs:773-777，
  注释直引 rangemap.hh:137）返回内部 records Vec **插入序**。顺序链两侧一致。
  该顺序有语义：MapState::initialize 用 `stable_sort`（varmap.cc:1078），相等
  (sstart,size,rangeType,flags,highind) 键（RangeHint::compare, varmap.cc:321-333）保插入序
  并传播进 restructure 合并。判定 ✓。
- `sym==0 continue` ↔ `symbols.get(entry.sym)` None continue ✓
- start=entry.getAddr().getOffset() ↔ entry.start ✓；ct=sym->getType() ↔ sym.dtype ✓
- flags=isTypeLocked?typelock:0 ↔ sym.typelock→TYPE_LOCK ✓；fixed/-1 ✓
- null rangemap 早退 ↔ materialize 为空表，等价 ✓

### 1.3 AliasChecker::deriveBoundaries — varmap.cc:633-655 vs src/varmap.rs:576（经 gather :692-704/:618 接线）

- 默认 `localExtreme=~((uintb)0)` / `localBoundary=0x1000000`；`direction==-1` 时
  localExtreme=localBoundary（:636-639 ↔ :584-588）✓
- hasModel 门 + 双 range 非空检查（local 仅作存在性检查，值不用——两侧同构，:645-647 ↔ :593-595）✓
- `localBoundary = param->getLast()`（paramrange **末** range 的 last）↔ `param.1` ✓
- direction==-1: `localBoundary=paramrange.getFirstRange()->getFirst(); localExtreme=localBoundary`
  （:650-651 ↔ :597-602）✓
- 511 接线: fspec.cc:2298-2307 逐字核实——负增长、stack addrSize>=4 时
  `paramrange.insertRange(spc, 0, 511)`。fixture case6 `local=1ff` 实证 ✓
- has_model 来源: func_proto_has_model（varmap.rs:1094-1105）回退序 = 约定名 → defaultfp →
  无 Architecture false，与 func_proto_param_range 同序；Ghidra FuncProto::setScope
  （fspec.cc:3879-3885）保证 model 恒挂，生产路径等价 ✓
- gatherInternal 初值修复（本 commit 核心）: `aliasBoundary = localExtreme`（:664 ↔ :662），
  非硬编码 ~0；fixture `extreme=ffffffffffffffff`（direction=1 保持 ~0）实证 ✓；
  direction 分支 continue（`offset<localBoundary` / `offset>localBoundary`，:673-678 ↔ :679-688）✓；
  收缩 `offset<aliasBoundary` ✓；无内联排序，sortAlias 独立成步（:726 ↔ sort_aliases:706，
  restructureVarnode :1279 ↔ :3092 调用）✓
- 方向来源差异: Ghidra `space->stackGrowsNegative()`，Rugra 传原型派生 bool
  （注释声明 cspec 中两者同源配置；fixture C++ 侧 SpacebaseSpace(...,true) 与 Rust true 一致）。
  记录为已声明约定，非缺陷。

### 1.4 ScopeLocal::restructureVarnode 编排 — varmap.cc:1256-1286 vs src/varmap.rs:2956-3106

编排序逐点对齐（Ghidra 行号 ↔ Rugra 行号）:
1. clearUnlockedCategory(-1)（:1259 ↔ :2965-3020 内联）— database.cc:2089-2107 cat<0 分支
   逻辑一致: category>=0 存活 / typelock 存活+unlock 已定义名 reset $$undef / else remove。
   minor: Ghidra 按 nametree（名字序）遍历，Rugra 按 Vec 插入序——仅影响
   buildUndefinedName 的占位符编号分配顺序，E2E defects=0 未见可观察差异。
2. MapState ctor 含 paramRange 剥离（:1260-1261 ↔ build_map_state:2919-2944，
   localrange copy + 逐 param range remove，varmap.cc:862-875 同构）✓
3. gatherVarnodes（:1267 ↔ :3055）；Rugra 额外 gather_spacebase（:3056）为父 commit 既有
   超集步骤，非本 commit write-set
4. gatherOpen（:1268 ↔ :3060）内嵌 checker.gather→addbase 循环→loadGuard 列表→storeGuard
   列表，顺序一致；alias[i]/addbase[i] 对位、index!=null→3 else -1、非指针→None(Ghidra NULL,
   "Do unknown array" :1230) ✓
5. **gatherSymbols 回灌（:1269 ↔ :3064）** ✓
6. restructure（:1270 ↔ :3072；LowlevelError 通道差异已登记 SCOPE-FINDOVERLAP-KEY-0001）
7. clearUnlockedCategory(function_parameter)（:1275 ↔ :3087，database.cc:2075-2090 cat>=0 分支）✓
8. clearCategory(fake_input)（:1276 ↔ :3088，database.cc:2022-2029 cat>=0 分支）✓
9. fakeInputSymbols（:1277 ↔ :3089）**先于** markUnaliased ✓
10. sortAlias（:1279 ↔ :3092，无条件、在 aliasyes 检查之前——两侧同位）✓
11. [aliasyes] markUnaliased + checkUnaliasedReturn（:1280-1282 ↔ :3099-3100；aliasyes 恒 true
    已登记 coreaction.rs:877-880 TODO）✓
12. alias 非空且 [0]==0 → annotateRawStackPtr（:1284-1285 ↔ :3104-3105）✓
- reset_local_window（:3044）为 Rugra 侧额外调用，差异已登记
  VARMAP-CROSSPASS-PERSISTENCE-0001（非本 commit 义务）

### 1.5 ScopeLocal::checkUnaliasedReturn — varmap.cc:414-428 vs src/varmap.rs:3189

- 三早退: getFirstReturnOp null / numInput()<2 / vn space != scope space（:417-420 ↔ :3192-3204）✓
- lower_bound(alias, offset) ↔ `partition_point(|&a| a < offset)`（:422 ↔ :3212）等价 ✓
- `*iter <= offset+size-1`（uintb 回绕）↔ `alias[pos] <= offset.wrapping_add(size).wrapping_sub(1)`
  （:425 ↔ :3211-3213）✓
- markNotMapped(space,offset,size,false) ↔ mark_not_mapped(offset,size,false)（:427 ↔ :3218）✓
- 依赖 alias 有序: 由编排第 10 步 sortAlias 前置保证，两侧同构 ✓

### 1.6 ScopeLocal::annotateRawStackPtr — varmap.cc:386-408 vs src/varmap.rs:3231

- 门: hasTypeRecoveryStarted（:389 ↔ :3233）/ findSpacebaseInput（:390-391 ↔ :3238）✓
- 过滤: `getEvalType()==special && !isCall()` skip；INT_ADD/PTRSUB/PTRADD skip
  （:396-399 ↔ :3250-3260）✓
- **两段式时序**: 先收集 refOps 再插 op（:393/:402 ↔ :3245/:3266）——插入会改 descend
  列表，先快照避免迭代失效，两侧一致 ✓
- slot=op->getSlot(spVn)（线性找 sp 槽）↔ inrefs 线性 Arc::ptr_eq 扫描（:404 ↔ :3267-3277）✓
- `newOpBefore(op,CPUI_PTRSUB,spVn,newConstant(size,0))` + `opSetInput(op,ptrsub->getOut(),slot)`
  （:405-406 ↔ :3279-3284）✓ — fd &mut 签名的正当依据
- PTRSUB 插入时序相对 checkUnaliasedReturn/markUnaliased: Ghidra :1284-1285 在两者**之后**，
  Rugra :3104-3105 同位（mark_unaliased→check_unaliased_return→annotate）✓

## 2. 双侧 fixture 自洽（机制 B2）

- 产物: `/tmp/rugra-wt-gatheropen-oracle/{ghidra,rugra}.stdout`
  `diff` IDENTICAL；双侧 sha256 同一 =
  `3b5e1b652697a3102edfad14df2211e6adb9c9cdb3e768faf9c1e76261b97494`，
  与 commit Fixture 块声明**逐字一致**。
- 6 case 输出与逐 case 声明吻合:
  - guard_open_hints → `char[32]@c0; int[8]@e0`（minItems=7 吸收 unanalyzed、store 外扩、
    outSize(8)>step(4) 拒无痕）
  - gather_symbols_reinput → locked_local 名/型/边界保持，相邻 int 得 `$$undef00000000`
  - category_clears → 仅 locked_param 存活
  - check_unaliased_return → marked 树去 [0x30,0x37]（`0-2f;38-1ff`）vs 别名@0x34 触达不动
  - annotate_raw_stack_ptr → `def=ptrsub:0`
  - derive_boundaries → `local=1ff|extreme=ffffffffffffffff|aliasboundary=200|probes=0,1,1`
- C++ 侧: 锁定 cpp 树重编 libdecomp.a（make.log 在 /tmp/rugra-wt-gatheropen-oracle/），
  模型走生产 XML decode（`<prototype ...><input/><output/></prototype>` 无窗口元素 →
  默认负增长 8 字节栈，param [0,511] / local [highest-999999,highest]，
  fspec.cc:2280-2315/2339-2353 逐字核实）；#define private/protected public + class struct
  只读观察窗。
- Rust 侧单测 test_derive_boundaries_model_gates 存在（src/varmap.rs:5109，静态确认；
  禁 cargo 未重跑，45/45 声明采信且不影响本判定——双侧 fixture 是机制 B2 的决定性证据）。

## 3. E2E 零位移声明核实（机制 B）

- 本复核重跑: `python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only`
  → **skeleton 1435 / defects 0 / numbering 0 / 116 函数参比**，与 commit Differential 块
  逐位一致（与 BLOCKSTRUCT-TIMEOUT-0001 已登记谱系相同，非干净数字但零位移成立）。
- 回流核实: `result/curl_cur.c` 与 `/tmp/rugra-gatheropen-curl.log` sha256 同一
  （`9b3a5d95...`），REFLOWED-SAME ✓。

## 4. fd &mut 变更影响面

- `examples/diag_stack.rs:98`: 单点 `&fd` → `&mut fd`，fd 为 main 内局部变量，无连锁借用。
- 生产调用方 `src/coreaction.rs:880`: `scope.restructure_varnode(fd)`，Action 上下文 fd 已为
  &mut，签名匹配（E2E 编译+运行通过为客观证据）。
- 变更正当性: annotateRawStackPtr 的 newOpBefore/opSetInput 突变 fd（varmap.cc:405-406），
  Rust 借用规则要求 &mut。判定 ✓。

## 5. REQUIRED-FOLLOWUP（不阻碍本判定）

### 5.1 [P2] add_guard 的 read-facing 未走 op 版（休眠 union 分歧）
- Rugra: src/varmap.rs:1803 `vn.get_type_read_facing()`（无 op，恒返回 v_type）
- Ghidra: varmap.cc:1009 `getTypeReadFacing(op)` — varnode.cc:639-645: needs_resolution 时
  `findResolve(op, slot)`；**TypePointer 覆盖了 findResolve**（type.hh:432,
  type.cc:1192-1202）：union 指针按 `fd->getUnionField(this,op,slot)` 解析到字段类型。
- 当前不可观察的原因: Rugra op 版 get_type_read_facing_op 的 findResolve 目前是 identity
  （varnode.rs:1383-1390），两版同值；union resolution 底层设施已存在
  （fd.union_map / unionresolve::UnionResolveMap，datatype.rs:995-1002 已按 ResolveEdge 查询），
  但 Var 层 read-facing 未接线。union 指针作为 guarded LOAD/STORE 地址且 union_map 已记录
  resolution 时（后续 pass 重入 restructureVarnode 的真实管线时序），双侧行为将分歧。
- 修正方向: Varnode read-facing 接 union_map 后，将 :1803 切到
  `get_type_read_facing_op(&op, 1)`（getIn(1) 恒 slot 1）。根因在类型系统基础设施
  （从底向上补齐），非本 commit 回归；双侧 fixture 均无 union 输入（休眠）。
  建议登记 TODO ID。

### 5.2 [P1-既有] fixture 无 metadata.json、Rust 侧不入 cargo
- `tests/oracle/varmap_gatheropen_guard_1204.metadata.json` 缺失（目录内其他 fixture 均有）；
  Rust 侧经 /tmp worktree 手动 rustc 编译（rustc.err 在 /tmp/rugra-wt-gatheropen-oracle/），
  非版本化 hermetic runner。commit message 已自我声明为 main agent 后续项
  （"hermetic runner + metadata.json 重钉为后续"）。按机制 B2 严格口径，该 fixture 的
  可重复性门禁尚未闭合——本复核以现存产物（双侧 stdout + sha256 + oracle tag）判定 6/6 MATCH，
  但重钉义务仍在。

### 5.3 观察记录（无需行动）
- add_guard 防御性早退（ct=None / in(1)/in(2)/output 缺失时 return）对应 Ghidra 前置条件
  保证不发生的解引用路径，不可观察。
- annotate_raw_stack_ptr 的 slot fallback（inrefs.len() vs Ghidra getSlot 未定义返回）与
  ptrsub.output None 跳过，均为不可达路径防御。
- gather_spacebase（Rugra 超集步骤，父 commit 既有）产生 Ghidra 无源的 fixed hints，插在
  gatherVarnodes 与 gatherOpen 之间；E2E 零位移覆盖该交互，本次不判。
- clearUnlockedCategory(-1) 内联的遍历序（Vec 插入序 vs nametree 名字序）仅影响
  buildUndefinedName 占位符编号分配顺序，无观察差异。

## 6. 结论

四件套（addGuard/gatherSymbols/deriveBoundaries+接线/annotateRawStackPtr+checkUnaliasedReturn
及 restructureVarnode 编排）在四类决定性语义上与锁定 oracle 逐行一致；编排序（含
gatherSymbols :1269 回灌、双清类 :1275-1276、sortAlias 前置 :1279、PTRSUB 末位 :1284-1285）
完整对齐；双侧 fixture 6/6 逐字节 MATCH（sha256 复核同一）；E2E 差分重跑零位移（1435/0/0/116
逐位一致，回流文件哈希同一）；fd &mut 影响面封闭。两项 follow-up（union read-facing 休眠分歧、
fixture 重钉）均非本 commit 引入或当前可观察，已列明修正方向。

**Cross-Review: APPROVE**
