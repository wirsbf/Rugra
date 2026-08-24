# R15 — SPLITDATATYPE-EXACTPIECE-0001 独立复核（机制 C）

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-splitdatatype`，分支 `agent/splitdatatype-exactpiece2`
  - `a5552de053d36bd2c397e61b78e4eb1e0421fc54`（align: port SplitDatatype exact-piece gate chain）
  - `ea7d5d19ea4a231eb09a5c672ffc0d5e9b35ea93`（test: pin bilateral gate）
- 复核 Agent：独立复核 agent（只读 worktree/git；本文件为唯一写产物）
- Oracle：`ghidra/` HEAD = `e40ed13014025f82488b1f8f7bca566894ac376b`（= 锁定 commit，已验证）；
  cpp subtree tree-id `b02e230a539c65de14e50f357d0ba834d8184f4f`（已验证 `git rev-parse HEAD:...cpp` 一致）
- 复核方式：亲自通读 subflow.cc:2208-2401 / 2673-2699 / 2701-3004、type.cc:4090-4117 / 1652-1663 / 1243-1247 / 2379-2385 / 174-177、
  type.hh:256/247、options.cc:978-1021、typeop.cc 13 处 arithmetic_op 注册行，再逐行对照 Rugra 实现。
  **未采信实现者 Alignment Evidence 块**。

## 判决

```
Cross-Review: REJECT
```

阻断性 MISMATCH 共 2 项（M-1 gate 语义、M-2 测试固化），另有 5 项非阻断建议（S-1..S-5）。
移植主体（categorize 分档序 / compat 组合门序 / Arc::ptr_eq / get_exact_piece 消费同源 / ctor 配置读取 /
apply 无配置 guard / c4e5ecf 三类红旗问题清除 / pins 自洽）**全部独立验证通过**——
REJECT 仅针对 hole 语义链，不否定本次移植的主体方向。

---

## 1. 四类语义核对（重点项）

### 1.1 categorize_datatype -1/0/1/2 分档序 — PASS
逐行对照 subflow.cc:2244-2284 vs src/subflow.rs:4888-4938：

| Ghidra | 行 | Rugra | 一致性 |
|---|---|---|---|
| TYPE_ARRAY + !splitArrays → -1；elem unknown&&size1 → 2；否则 1 | 2249-2255 | array_category | ✓ |
| TYPE_PARTIALSTRUCT→parent ARRAY 同上 | 2258-2264 | PartialStruct→Array | ✓ |
| TYPE_PARTIALSTRUCT→parent STRUCT：splitStructures→0，**不查 numDepend** | 2266-2269 | PartialStruct→Struct 直接 0 | ✓ |
| TYPE_STRUCT：splitStructures && numDepend>1 → 0 | 2271-2275 | fields.len()>1（numDepend=field.size(), type.hh:526） | ✓ |
| TYPE_INT/UINT/UNKNOWN → 2；TYPE_BOOL → default -1 | 2276-2279 | matches! Int|Uint|Unknown | ✓ |

### 1.2 testDatatypeCompatibility 组合门序与三分支 — PASS（除 1.4 M-1）
门序（cc:2299-2314 vs rs:4964-4989）逐条同序：
1. inCat<0→false；2. outCat<0→false；3. out==2&&in==2→false；4. `!inConstant && inBase==outBase && STRUCT`→false；
5. isLoadStore && out==2&&in==1→false；6. isLoadStore && in==2&&!const&&out==1→false；7. isLoadStore && in==1&&out==1&&!const→false。
三分支（in==2 走 out 组件 / out==2 走 in 组件 / both 组件）、hole 拒绝条件
（`pieces.size()==1` 初洞；`sizeLeft==0 && size.size()==2` 双片 padding，cc:2329-2332/2346-2349）、
both-composite 降取循环结构（cc:2358-2373，hole→getBase(小侧尺寸)，非 hole→getComponent(cur,0)）、
终判 `pieces.size()>1`（cc:2379）——全部同构。
in==2 分支的 `inConstant ? curOut : unknown` 抛弃原语（cc:2324）亦一致（rs:5010-5014）。

### 1.3 `Arc::ptr_eq` 同指针拒绝 — PASS
cc:2307 `inBase == outBase` 是 `Datatype*` 指针相等；rs:4976 `Arc::ptr_eq(in_base, out_base)` 是 Arc 语义下
的同一对象判定。配合前置 `!in_constant` 与 `getMetatype()==TYPE_STRUCT` 三条件的求值顺序一致。

### 1.4 getComponent / get_hole_size — **MISMATCH（见 §3 M-1）**
do-while 结构（cc:2221-2233 vs rs:4847-4874）、hole 用**原始 ct/原始 offset**（cc:2224 `ct->getHoleSize(offset)`
而非 curType/curOff；rs:4851 同）、hole cap 8（cc:2226-2227）、array 续降条件 `curOff!=0 || ARRAY`
（cc:2233；rs:4869 `!(cur_off != 0 || Array)` 取反早退）——结构本身对齐。
但 hole 尺寸来源 `get_hole_size` 的 Base fallback 与 oracle 相反，详见 M-1。

### 1.5 get_value_datatype 与 get_exact_piece 消费同源 — PASS
- cc:2910-2938 vs rs:4760-4828：`in(1)` read-facing 类型 → 非 PTR 拒 → PTRREL 取 parent/byteOffset、
  plain 取 ptrTo/0 → `alignSize<size` 且标量集 {INT,UINT,BOOL,FLOAT,PTR} 且整除 → `getArray(numEl)`
  → else-if STRUCT/ARRAY → `getExactPiece(baseOffset,size)` → 默认 null。分支互斥性与 fall-through 一致
  （Ghidra 标量不整除时直接落尾部 return null，Rugra 同）。
- get_exact_piece（typefactory.rs:1684-1726 vs type.cc:4090-4117）：do-while 等价 loop；
  `size+curOff` int8 提升 → Rugra i128（rs:1697，注释说明）；perfect-size 返回原 Arc（canonical 身份）；
  UNION → partial union；lastType STRUCT/ARRAY → partial struct；enum&&!stripped → partial enum；否则 None。逐行一致。
- 四生产调用点同源：Rugra 侧 database.rs:325（↔database.cc:161）、variable.rs:694（↔variable.cc:560）、
  funcdata.rs:271（local symbol 辅助）、ruleaction.rs:12154（↔ruleaction.cc:7665）+ 本次 subflow.rs:4825
  （↔subflow.cc:2937）全部经 `Architecture.types` 同一工厂 Arc（apply_op 取 `fd.get_arch().types`，rs:5654/5707）。

### 1.6 ctor / apply 链 — PASS
- ctor（cc:2701-2709 vs rs:4734-4747）：types=glb->types；splitStructures/splitArrays 仅读 struct/array
  两位（pointer 位不在 ctor 消费，与 oracle 一致）；isLoadStore=false。
- RuleSplitLoad::applyOp（cc:2970-2983 vs rs:5647-5677）/ RuleSplitStore（cc:2991-3004 vs rs:5700-5730）：
  size 取 out()/in(2)；getValueDatatype null→0；metatype∈{STRUCT,ARRAY,PARTIALSTRUCT}；无其他条件。
- RuleSplitCopy 前置门（cc:2954-2957 vs rs:5606-5618）等价。
- isArithmeticInput/Output（cc:2677-2688/2693-2699 vs rs:5483-5498）：descend 迭代任一算术 / def 算术。
  **13 个 arithmetic_op 注册行逐行独立确认**：typeop.cc:1171 INT_ADD、1322 INT_SUB、1336 INT_CARRY、
  1352 INT_SCARRY、1368 INT_SBORROW、1384 INT_2COMP、1621 INT_MULT、1635 INT_DIV、1655 INT_SDIV、
  1675 INT_REM、1695 INT_SREM、2228 PTRADD、2304 PTRSUB（共 13 处 `addlflags = arithmetic_op`），
  与 rs:5461-5477 集合完全一致。

---

## 2. 红旗自查（c4e5ecf 三类问题）— 全部清除

1. **非 Ghidra 配置 guard**：a5552de 的三个 apply_op 均无 `split_datatype_config` 检查（唯一消费点 =
   `SplitDatatype::new`，rs:4736-4744，与 cc:2706-2707 同位）。`grep` 全文件确认 subflow.rs 中
   OPTION_*/split_datatype_config 仅出现于 ctor（4736-4744）与测试（6521+）。c4e5ecf 的 apply 层
   config guard 已不存在。✓（注意 OPTION_POINTER 位本身是 Ghidra 真有的 options.hh:339，非自创。）
2. **本地复制 helper**：`collect_components` / `immediate_offset_after` 在 src/subflow.rs 出现 0 次
   （commit diff 中为纯删除行）。exact-piece 消费全部走 canonical TypeFactory。✓
3. **B2 fixture**：`tests/oracle/splitdatatype_exactpiece_1204.{cc,rs,metadata.json}` +
   `tools/run_splitdatatype_exactpiece_oracle.sh` 存在；20 记录双侧 expected stdout sha256 相同
   （`c11eb5af…73bea`）；rust fixture 通过 `use rugra::subflow::{RuleSplitLoad, RuleSplitStore, SplitDatatype}`
   等驱动生产 API（32 处调用点，无本地重实现）；C++ 侧以 `#define private public` 探针观察私有 gate
   （metadata analysis_options.gate_observation 已声明该观察通道）。✓

---

## 3. MISMATCH（阻断）

### M-1 `get_hole_size` Base fallback ≠ Ghidra 基类 `getHoleSize`（gate false-accept）

- Ghidra：`type.hh:256`
  ```cpp
  virtual int4 getHoleSize(int4 off) const { return 0; }   // 基类：标量/未覆写类型无 hole
  ```
  TypeStruct::getHoleSize（type.cc:1652-1663）委托字段：`newOff < field.size → curfield.type->getHoleSize(newOff)`
  → 标量字段 → 基类 → **0**。TypeArray（1243-1247）委托元素，TypePartialStruct（2379-2385）clamp。
  即 oracle 中"hole"仅存在于 struct 字段间隙/尾部；**标量内部任意偏移都不是 hole**。
- Rugra：`src/type_system/datatype.rs:1081-1088`
  ```rust
  _ => { let sz = self.get_size() as i64;
         if off < 0 || off >= sz { 0 } else { sz - off } }   // Base fallback 返回 size-off
  ```
  文档注释自述 "Base: returns the remaining size from off"——**Ghidra 没有任何类有此基类语义**；
  `getSize()-off` 是 TypeStruct::getHoleSize 尾部（到结构末尾距离，type.cc:1663）的语义，被错误下放到
  所有非组合类型。引入于先前 commit `3c8d738`，但本次移植的 `SplitDatatype::get_component`
  （rs:4851 `ct.get_hole_size(offset)`、both-composite 降取 rs:5072/5084 `get_component(&cur_x, 0)`）
  直接消费它，gate 链行为被污染。

后果（oracle 同输入下行为分歧）：
- **both-composite 对标量降取**：in=int(4) vs out=short(2)，非 hole 时 cc:2363
  `curIn = getComponent(curIn,0,inHole)` → int->getSubType(0)=null（type.cc:174 基类）+
  int->getHoleSize(0)=0 → 返回 null → cc:2364 **return false**（NO_CHANGE）。
  Rugra：get_component(int,0) → Base fallback hole=4-0=4 → 返回 (unknown4, hole=true) →
  继续内层循环 → 最终接受拆分。**false-accept（过度拆分），与 my_fwrite 误拆同方向的病灶。**
- **offset 落在标量字段内部**：getComponent(struct, off-in-scalar-field) 的
  `ct->getHoleSize(offset)` → TypeStruct 委托 → 字段(标量)->getHoleSize → oracle 0 → null → 拒；
  Rugra 委托后 Base fallback 返回 size-off>0 → 填 unknown → 接受。
- hole cap 8 的边界同样受影响（Base fallback 对 >8 标量在 off 小处返回 sz-off，被 cap 到 8，
  oracle 应为 0）。

修正方向（自底向上，铁律 1.4/1.6）：`Datatype::get_hole_size` 非 Struct/Array/PartialStruct（及已建模的
Spacebase 委托）fallback 改为返回 0，对齐 type.hh:256；随后排查既有调用方（typefactory/ruleaction 等）
是否有依赖错误 fallback 的行为（需回归其 fixture），并为 `SplitDatatype::get_component` 补
标量内部偏移/both-composite 标量降取的 bilateral 记录（见 M-2 一并重钉）。

### M-2 `test_split_copy_size_mismatch_fills_unknown_pieces` 把 M-1 固化为期望行为

`src/subflow.rs`（test module，原 `test_split_copy_size_mismatch_is_no_change` 改写）：
in=struct{char@0;int@1}（constant）vs out=struct{char@0;short@1;short@3}，断言 `CHANGE`，
注释引用 cc:2355-2364 声称 "unknown2 over the int/short prefix … mirroring Ghidra's getComponent hole fillers"。

oracle 同输入逐行推演（亲自执行语义，非采信声明）：
- 旧断言 NO_CHANGE 的原始动机（尺寸不匹配即拒）在 oracle 下**歪打正着**——但拒绝点不是
  testDatatypeCompatibility 的组合门，而是 cc:2363→type.hh:256 的 null 降取（M-1）。
- piece0 char/char 匹配后，curOff=1 处 curIn=int(4)>curOut=short(2) 且非 hole →
  getComponent(int,0)=null → **cc:2364 return false → NO_CHANGE**（constant 与否不影响该路径）。
- 新断言 CHANGE 的"3 片 unknown 填充"每一片都经由 M-1 的非法 Base hole：piece1 走
  get_component(int,0)→hole 4→unknown4→(hole)→unknown2；piece2 走 struct 委托
  int.get_hole_size(2)=2 → (unknown2,hole)。
- 即：**该测试在 Ghidra oracle 下必然 NO_CHANGE，Rugra 断言 CHANGE**——机制 B2 意义上的 MISMATCH
  测试，且注释用 cc 行号给非 oracle 行为背书（红旗 D：cited-line-drift）。

修正方向：修 M-1 后将此测试重钉为 NO_CHANGE；若要保留"unknown 填充照拆"的正向覆盖，构造真正的
Ghidra hole 场景——out 侧**字段间隙 padding**（TypeStruct::getHoleSize 的 lower-bound-field 间隙距离，
type.cc:1661-1663），那才是 cc:2361/2368 `getBase(小侧尺寸)` hole-filler 的合法触发条件，
并补双侧 fixture 记录。

---

## 4. 三个旧测试更新正当性逐个裁定

| 测试 | 改动 | 裁定 |
|---|---|---|
| `test_split_datatype_constructs` | 无 arch → flags 断言 false（原 true） | **正当（非阻断）**。Ghidra Funcdata 恒有 arch、默认 config=struct\|array\|pointer（architecture.cc:1431-1432）；Rugra 无 arch 是 C++ 不可达状态，fail-closed（false→categorize -1→NO_CHANGE）为保守方向。注释如实声明。 |
| `test_split_copy_performs_real_transform` | in_vn 从 function-input 改为 constant | **正当**。双重修正：(a) 旧版 in_vn 注册为 input 会被 testCopyConstraints cc:2390 `inVn->isInput()` 直接拒——旧测试在 oracle 下本不可能 CHANGE；(b) in/out 同一 struct Arc 非常量会撞 identity gate cc:2307-2308；constant 初始化整结构拆分正是该 gate 的放行例外。与 oracle 语义一致。 |
| `test_split_copy_size_mismatch_fills_unknown_pieces` | NO_CHANGE → CHANGE | **不正当 → REJECT（M-2）**。oracle 同输入 NO_CHANGE；新断言建立在 M-1 的非 oracle Base hole 上。 |

---

## 5. 双侧 fixture 20 记录与板载验收四项

expected_lines（metadata）20 条，与 input_manifest.cases 20 例一一对应；双侧 expected stdout sha256 相同。
四项板载验收逐条核对：

1. **FILE*+8 不误拆**：`apply|case=file_opaque8_store|ret=0|ops_added=0|orig_kept=1`（getValueDatatype
   exact-size 命中 type.cc:4105 返回整 struct → apply metatype 门放行 → splitStore gate 拒）✓
2. **ProgressData partial**：`gv|case=progress16|result=partial_struct:16@0/parent=struct:24` +
   `apply|case=progress16_store|ret=1|stores=0:4,4:4,8:4,12:4`（getExactPiece→PartialStruct→
   splitStore 4 字段片）✓
3. **identity 保留**：store `orig_kept=1`（cc:2879-2880 原 STORE 对象转首片，rs:5380-5381 op_set_input
   复用）；load `orig_gone=1`（cc:2797 destroy，rs:5305 op_destroy）✓
4. **二轮稳定**：`stab|global_changes=0` + 各 apply 记录 `stab=0` ✓

**但**：20 记录未覆盖 M-1/M-2 的 both-composite 标量降取与标量字段内部偏移路径
（iofile8_prim 的 hole 是 struct padding 间隙——合法 hole 场景，双侧一致）。故 fixture 的 20/20 MATCH
为真但不证明 M-1 路径；metadata coverage 亦未把该路径登记为 UNTESTED（登记缺口，随 M-1 一并补）。

pins 自洽（三方验证 git 对象 vs metadata vs runner）：
- candidate commit `a5552de05…` / tree `62b3b39a…` ✓（git rev-parse）
- critical blobs：src/subflow.rs `cae7b73c…`、Cargo.toml `f15ed7d0…`、Cargo.lock `9736a3c5…`、
  build.rs `a0c81c85…` ✓（git ls-tree；双形态区分正确：blob id vs 文件 sha256）
- comparand sha256（文件级）：subflow.rs `982ee065…`、cpp/rust fixture、runner `8b572914…`、
  docs/api/subflow.md、Cargo.toml/lock/build.rs 全部与 worktree HEAD(=ea7d5d1) sha256sum 一致 ✓
- oracle：commit `e40ed13…`、cpp tree `b02e230a…`、Makefile blob `ca0719fa…` ✓
- runner 从 metadata 读取 candidate 三件套并 rev-parse/ls-tree 校验，`reject_pending` 拒绝 PENDING；
  ea7d5d1 重钉正确（本复核期间 metadata 显示的 commit 即 a5552de，非 PENDING）✓

---

## 6. 声明的剩余差异归属抽查

| 差异 | 声明位置 | 代码实证 | 裁定 |
|---|---|---|---|
| RootPointer::find 多跳/addrTied duplicateToTemp | subflow.md、metadata rewrite_op_shape | RootPointer 仅 `new()`（rs:4712-4723），split_load/store 直接用 in(1) 单跳 | 归属合理；flat_array_pointer_apply UNTESTED 登记（oracle 在 find 拒、Rugra 无对应机制）诚实 |
| op 形状分歧（PTRSUB/PTRADD vs INT_ADD/SUBPIECE） | metadata rewrite_op_shape UNTESTED | rs:5283-5294/5377-5390 INT_ADD；oracle buildPointers PTRSUB/PTRADD | 归属合理；fixture 以有效偏移+尺寸+identity 投影对拍，未冒充 op-DAG 对齐 |
| splitStore LOAD 值回溯 cc:2817-2830 | subflow.md | rs:5344-5348 直接 get_type_read_facing，无 loadOp 重试 | 归属合理 |
| splitLoad COPY-follow cc:2761-2769 | subflow.md | rs:5243-5257 无 copyOp 逻辑 | 归属合理 |
| OptionSplitDatatypes pointer 位 | **未声明** | Ghidra 消费点 = options.cc:1012-1020 `toggleAction("splitcopy"/"splitpointer")`（RuleSplitLoad/Store 属 "splitpointer" Action group，coreaction.cc:5706-5708）；Rugra `grep splitpointer|splitcopy src/coreaction.rs` 零命中，Action 层 toggle 不存在 | **声明缺失 → S-1**（TODO_BOARD 任务描述明确要求"在 Action/group 层实现 pointer 配置"，实现未做且未列入任何残留差异清单） |

---

## 7. 建议（非阻断）

- **S-1**：登记并（按 TODO 要求）实现 pointer 位的 Action/group 层语义（options.cc:1012-1020 的
  splitcopy/splitpointer toggle），或在 SPLITDATATYPE-EXACTPIECE-0001 剩余差异中显式登记该缺口。
- **S-2**：`get_value_datatype` 的 legacy PTRREL side-table 回退（rs:4787-4789，get_parent/get_byte_offset
  缺失时退 (ptr_to,0)）是 Rugra 特有状态路径，metadata 未登记 UNTESTED；建议补条目。
- **S-3**：`test_datatype_compatibility` 开头 `self.data_type_pieces.clear()`（rs:4963）：Ghidra 函数体无
  clear（由 splitter 栈构造 + splitStore 重试路径 cc:2829 显式 clear 保证）。所有 oracle 调用路径下行为
  等价（非 MISMATCH），建议加注释说明该等价性论证，避免后人误读为 oracle 原文。
- **S-4**：split_load/split_store 的 out/in 类型缺省用 `get_type_read_facing()`（无 op 参，rs:5253-5257/
  5344-5348），oracle 是 `getTypeReadFacing(loadStore/storeOp)`（cc:2772/2822，带 op）；Rugra None→
  unknown_of 的 fail-closed 可接受，但 per-op read-facing 语义差异建议随 RootPointer 移植一并核对。
- **S-5**：`categorize_datatype` 的 `Base(_)|Void(_)` 臂与 default 臂重复（rs:4929-4936），可合并。

---

## 8. 复核方法与可重复性

- Ghidra 原文通读范围：subflow.cc:2205-2450、2670-2700、2700-3004；type.cc:174-177、920-930、1234-1247、
  1640-1663、2363-2392、4090-4117；type.hh:247/256/526；options.cc:978-1021；architecture.cc:1420-1433；
  typeop.cc 13 处注册行（每处以 sed 定位类名归属）。ghidra HEAD 校验 = `e40ed13…`。
- Rugra 侧通读：src/subflow.rs:1-120（模块缺口声明）、4660-5730（SplitDatatype 全部成员 + Rule 三 apply +
  free helpers）、type_system/datatype.rs:880-930/1064-1090、type_system/typefactory.rs:1650-1726、
  database.rs/variable.rs/funcdata.rs/ruleaction.rs 调用点上下文、测试模块 diff 全量。
- 未运行任何构建/测试（只读约束）；fixture 双侧一致性采信 pins 三方自洽 + expected sha256 相同的形式证明，
  并以静态推演定位 M-1/M-2（其证明链仅依赖源码语义，不依赖运行）。

## 9. 第一轮结论（对 a5552de+ea7d5d1）

移植主体与 oracle 逐行对齐（§1 六项全 PASS），c4e5ecf 三类红旗问题确认清除，pins/fixture 骨架自洽。
但 `get_hole_size` Base fallback（datatype.rs:1081-1088）与 Ghidra 基类 `return 0`（type.hh:256）相反，
使本次移植的 `get_component` hole 路径在 both-composite 标量降取与标量字段内部偏移两类输入上
false-accept（oracle NO_CHANGE → Rugra 拆分），且新测试 `test_split_copy_size_mismatch_fills_unknown_pieces`
将该非 oracle 行为断言为 CHANGE 并引用 Ghidra 行号背书。按机制 C 判定准则（任一 MISMATCH → REJECT）：

**Cross-Review: REJECT**（修复后提请重审；已于 §10 完成）

---

## 10. 返修复审（对 516abce + 2a43884，2026-08-25）

返修对象：`516abce3bf747c6890d42f0451ba7108e8e999cf`（fix 本体）+ `2a43884e936426ab5e6170c797b04076beb0df3f`
（pins 重钉，纯 PENDING→实际值，无代码）。复核方式同首轮：亲读 diff 与两侧源码推演，未采信 commit message。

### 10.1 M-1 — PASS

- **fallback 修复**：datatype.rs 基类臂 `_ => 0`，引用 type.hh:256 逐字（`virtual int4 getHoleSize(int4 off)
  const { return 0; }`），注释正确说明旧 `size-off` 是 TypeStruct 尾规则（type.cc:1663）被错误下推。
- **三覆写臂未动**：Struct/PartialStruct 臂零改动；Array 臂仅补 `.max(1)` 除零护栏注释（该护栏原已存在）。
- **调用方审计核实**：全库 `get_hole_size` 生产调用唯一 = src/subflow.rs:4851（`SplitDatatype::get_component`
  hole 路径）；datatype.rs 内部为三覆写臂互相委托（struct→字段 / array→元素 / partial→container）与测试断言；
  typefactory/ruleaction/varmap/rule 等零调用。旧 `size-off` 语义无其他依赖者——审计结论成立。
- **既有测试重钉正确性（独立 oracle 推演）**：两个 datatype 测试的 `get_hole_size(0)==4→0`
  （重叠字段委托进标量 → 基类 0）与 `get_hole_size(-1)==1`（type.cc:1661-1662 前字段距离）均与 Ghidra
  推演一致；PartialStruct clamp 弃用"标量内部"场景、改用真 struct 间隙 `ps_gap=[1,3)`：
  `min(到 int@4 的间隙 3, 剩余 2)=2`——type.cc:2379-2385 + 1652-1663 逐行验证正确。
- **判别 case `mismatched_scalar_desc` 判别力证明（静态推演，双侧 case 构造逐行同构、均走生产
  `SplitDatatype::split_copy` / oracle `splitter.splitCopy`）**：
  - 输入：in=struct{uint1@0;uint4@1} vs out=struct{uint1@0;uint2@1;uint2@3}，in 常量。
  - **修复前树（a5552de）**：curOff=1 处 uint4(4)>uint2(2) 非 hole → `get_component(uint4,0)` →
    Base fallback hole=4-0=**4** → (unknown4,hole) → 内层再降 unknown2 → piece1；curOff=3 处
    struct 委托 `uint4.get_hole_size(2)=4-2=2` → (unknown2,hole) → piece2；3 片 → `ok=1` ≠
    oracle `ok=0` → **记录 FAIL（判别力成立）**。
  - **修复后树（516abce）**：`get_component(uint4,0)` → hole=**0** → None → both-composite 分支
    `None => return false`（≡ cc:2364 null 即 return false）→ `ok=0` = oracle → PASS。
  - oracle 侧（.cc fixture）同输入直调真实 `splitCopy`，expected `ok=0`（cc:2363 经 type.hh:256）。

### 10.2 M-2 — PASS（正反两向钉住）

- **反向**：`test_split_copy_mismatched_scalar_descent_rejected`（原 fills_unknown_pieces 改名）：
  断言 NO_CHANGE 且 `ops_before` 不变；引用链修正为 subflow.cc:2363-2364 + type.cc:174（基类 getSubType
  null）+ type.hh:256；注明 constant 不影响该路径。与首轮 REJECT 推演一致。
- **正向**：新增 `test_split_copy_field_gap_hole_filler_accepted`：in struct{a4@0;b4@4;c4@8} vs
  out struct{a4@0;b4@8;c4@12}。独立推演 oracle：curOff=4 在 out 真字段间隙（TypeStruct::getHoleSize
  = 到 b@8 距离 4）→ `getComponent` 返回 (unknown4, isHole)（cc:2226-2229 的合法 hole filler）→
  in=b(4) 尺寸直配 → piece1(b,unknown4)；hole 拒绝门不触发（both-composite 分支无 hole 拒绝，且非
  primitive 分支的 len==1/双片条件）→ piece2(c@8,b@8) → 3 片 CHANGE。Rugra 同路径同结果。
  合法 filler（字段间隙）与非法 filler（标量内部）双向钉住。

### 10.3 登记完备性 — PASS（与代码一致）

| 项 | 登记位置 | 核实 |
|---|---|---|
| S-1 pointer 位 Action toggle | coverage `option_splitdatatypes_pointer_toggle` = REGISTERED GAP（options.cc:999-1022 / 1012-1020，归属 A49/OPTIONS 链）；analysis_options `option_splitdatatypes_apply` 同述 | ✓ 与 options.cc:1012-1020、coreaction.cc:5706-5708 事实一致；归属合理（Action/group 层非本 slice write-set） |
| S-2 legacy PTRREL 回退 | coverage `legacy_ptrrel_side_table_fallback` = UNTESTED | ✓ 对应 subflow.rs get_value_datatype IS_PTRREL 缺 parent 的 (ptr_to,0) 回退 |
| S-4 per-op read-facing | coverage `per_op_read_facing` = UNTESTED | ✓ 对应 cc:2772/2822 带 op vs Rust 无 op + unknown_of fallback |
| S-3 clear 等价注释 | subflow.rs test_datatype_compatibility 开头（oracle 无 clear；splitter 栈构造 + splitStore cc:2829 唯一显式再入口的等价性论证） | ✓ 落码 |
| S-5 match 臂合并 | categorize_datatype 删除重复的 Base\|Void 臂 | ✓ 行为等价（default 臂匹配集相同） |

### 10.4 fixture 20→25 与 pins 重钉 — PASS

- expected_lines 25 条；新增：`gv scalar_field_interior`（relptr 偏移 2 落 uint8 标量内部 → getExactPiece
  null，type.cc:4108-4115 终点 lastType 标量 → null——独立推演正确）、`split mismatched_scalar_desc`（判别
  case）、`initial_hole_window` / `two_piece_padding`（cc:2329-2332 两条拒绝边界）、`padding_filler_middle`
  （合法中位 hole filler，ok=1|pieces=0:4,4:4,8:4）。对应 coverage 四项 MATCH + 判别力声明；
  `rewrite_op_shape` / `flat_array_pointer_apply` 保持 UNTESTED（诚实未升级）。
- 双侧 expected stdout sha256 相同（`158dcac7…5d76f6`）。
- pins（三方验证）：candidate `516abce` / tree `cca1ae62`（git rev-parse ✓）；critical blobs 5 个
  （subflow.rs `73226c08`、**datatype.rs `ac18e9e3` 新增为 critical blob——修复载体，合理**、Cargo.toml/lock、
  build.rs，git ls-tree ✓）；comparand 文件 sha256 与 worktree(=2a43884) sha256sum 逐项一致 ✓；
  2a43884 diff 纯 PENDING→实际值，无夹带。首轮板载四项验收记录在 25 条中保留。

### 10.5 回归面检查 — 无回归

返修未触碰 gate 链主体（get_value_datatype / get_component 结构 / test_datatype_compatibility 分支逻辑 /
apply 三入口）；改动 = 基类 hole fallback、注释（S-3）、等价臂合并（S-5）、测试与 fixture。
首轮 §1 六项 PASS 结论继续有效。

### 10.6 最终结论

M-1（自底向上修复 + 判别力证明 + 调用方审计无遗漏）、M-2（正反双向钉住）、S-1..S-5（登记/落码一致）
全部核实；fixture 25/25 双侧一致、pins 三方自洽、无回归面。首轮流序 UNTESTED/REGISTERED 的
rewrite_op_shape / flat_array_pointer_apply / S-1 / S-2 / S-4 保持如实登记，未冒充 MATCH。

**Cross-Review: APPROVE**（对 516abce+2a43884；后续对该链的任何实现变更将使本批准自动失效并需重审）
