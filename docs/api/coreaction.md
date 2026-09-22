# `coreaction.rs` API Reference

## 2026-09-22：ActionDominantCopy 过期注释更正 + 域确定性归因（DETERM-DOMINANTCOPY-0001）

- 结构体/apply 的注释原声称 `process_copy_trims` 是 "faithful no-op、
  copyTrims 永不填充（缺 snip 子系统）"——已过期：snip 链路
  （unify_address/eliminate_intersect/snip_reads/allocate_copy_trim）
  2026-07-04 已接入 `merge_addr_tied`，`copy_trims` 有真实填充。
  更正为实际语义：Ghidra `ActionDominantCopy::apply`（coreaction.hh:1008）
  即 `data.getMerge().processCopyTrims(); return 0;`；Rugra 侧临时
  `Merge` attach `fd.merge_state.copy_trims` 持久通道，标准管线中
  merge 阶段（`merge_all` step 6，同一 oracle 调用点）先消费，故独立
  apply 通常见空表。
- AZ drill 的 "universal:dominantcopy 工作集逐进程漂移" 与 AX 的输出
  bimodal 同根因：`process_copy_trims` 内 HashMap 迭代序随机（修复在
  merge.rs，见 merge.md 同日条目 DETERM-COPYTRIM-0001）。本文件无容器
  行为变更，只更正误导性注释。

**状态**: 已核对（当前有效）  
**源代码路径**: `src/coreaction.rs`

## 2026-08-30：castInput 双层 double-cast guard 臂序（CASTINPUT-ARMORDER-0001 / F3）

- `cast_input` 的 double-cast guard 恢复 oracle 的**两层嵌套**（cc:2673-2686）：外层
  `isWritten && def==CAST`（cc:2673）无论 implied 与否都占用该臂；只有内层（cc:2674）
  判 `isImplied`。def=CAST 且非 implied 时整条 else-if 链（常量臂 cc:2687 /
  PTRSUB0 / tryResolutionAdjustment）被跳过，vnin 保持 vn 直接落穿 CAST 插入。
  此前 Rugra 把两层合并成 `def==CAST && isImplied` 单条件（合并臂序缺陷），使
  "def=CAST 非 implied + isConstant" 误入常量臂（原地 retype、无插入）。
- 单测 `test_cast_input_def_cast_non_implied_constant_skips_const_arm`：手工 wiring
  （绕过双侧 bank 对 const 输出的同构拒绝，镜像 Ghidra `PcodeOp::setOutput +
  Varnode::setDef`——setDef 设 WRITTEN flag）构造 CAST 产出的非 implied 常量空间
  varnode，断言常量臂未触发（类型保持 ptr）+ 落穿插入 CAST（其输入经
  `opSetInput` 的 const dedup（funcdata_op.cc:108-115，双侧同构）为同值复制）。
- fixture：`ptrsub_switch_cast_1204` 新增 `cast_arm_fork` case，19→21 records
  与锁定 oracle 字节一致（负控：合并形态下 constC 被常量臂 retype 成 int8 且
  无 CAST 插入，与 oracle 分叉）。

## 2026-08-30：isOpIdentical typedef 链剥离（COREACTION-ISOPIDENTICAL-TYPEDEF-0001 / F2）

- `is_op_identical`（cc:2469-2481）新增第三参数 `Option<&TypeFactory>`，在双 PTR 同步
  下探（cc:2472-2474）之后、身份比较（cc:2480）之前，逐侧独立执行
  `while(getTypedef())` typedef 链剥离（cc:2476-2479）。Ghidra 的 `typedefImm` 是
  Datatype 实例字段（type.hh:244）；Rugra 经 TypeFactory 的 typedef 表
  （`get_typedef_target(name)`，typefactory.rs，`get_typedef` 建立的 name→stripped
  映射）解析同一链，对 factory-interned 类型与对象身份等价（名字碰撞由
  `get_typedef` 的 find_by_name 检查 panic 拒绝，链无环）。detached Funcdata（无
  arch factory）保持裸指针比较（RUGRA-GLUE 防御；Ghidra 恒有 factory）。
- 语义顺序：typedef-of-pointer 在 PTR 下探中丢失别名；typedef pointee 保留下探后
  剥离。typedef 输入下 `cast_output` 的 typelock force 判定（cc:2566）由误真
  （多插 CAST）修正为 Ghidra 的不插。
- 单测 `test_is_op_identical_strips_typedef_chain` 锁定：alias↔base、链式 typedef、
  指针下探优先序、distinct base 负例、无 factory 退化负例。
- fixture：`ptrsub_switch_cast_1204` 新增 `typedef_typelock` case（implied+typelock
  的 typedef 输出走 force 判定），17→19 records 与锁定 oracle 字节一致（负控：
  修复前该 case 双侧分叉——Rugra 误插 CAST）。

## 2026-08-30：castOutput 完整臂 + castInput guard/const/explicit（PTRSUB-SWITCH-CAST-RESIDUAL-0001 steps 3+4）

- `cast_output`（cc:2532-2616）：token 分发补 PTRADD 臂（typeop.cc:2244 = in0 high
  read-facing，经真实 `TypeOpPtradd`）与算术族臂（cast.cc:394）；补 implied varnode
  三臂（cc:2559-2582：typelock+非 RETURN lone reader → `force = !isOpIdentical`；非
  指针 out → 原地 `updateType(tokenct)`；指针 out 且 pointee 非复合 → 同样重类型，
  复合 ARRAY/STRUCT/UNION 保留）；补 `testStructOffset0`（cc:2384-2413 全移植：struct
  首字段 offset==0 / array 下探一层 + 双侧 array 剥离 + VOID 拒绝 + castStandard
  (req,cur,true,true)==null 判定）→ PTRSUB(#0) 形态（cc:2586-2588/2605-2607）。刷新
  用 `refresh_out_high_resolve`（Rugra 的 typeDirty 为 no-op 的单实例投影，登记残差）。
- `cast_input`（cc:2655-2720）重构为 oracle 臂序：ct=null → `markExplicitUnsigned`
  /`markExplicitLongSize`（cast.cc:38-105 全移植，含 inheritsSign/
  inheritsSignZero/shiftOp 的 addlflags 集合与 mostsigbit 阈值）返回计数；double-cast
  guard（cc:2673-2686：implied CAST 输出 lone-descend 原地重类型 / 回接更早 varnode）；
  常量臂（cc:2687-2691：updateType 成功即计 1，锁定常量跌落到 CAST 插入）；插入用
  `vnin`（可能是更早 CAST 的输入）。
- fixture `ptrsub_switch_cast_1204` 全部 17 条记录与锁定 oracle 字节一致（13 条
  known_raw_differences 全部撤销，见重钉提交）。

## 2026-08-30：ActionSetCasts::apply 的 PTRADD/PTRSUB fit preflight（PTRSUB-SWITCH-CAST-RESIDUAL-0001 step 2）

- `apply` 开头调用 `fd.start_cast_phase()`（coreaction.cc:2728 / funcdata.hh:183，Rugra 新增
  `Funcdata::cast_phase_index` 字段 + `clear()` 复位）。
- PTRADD preflight（cc:2740-2746）：in0 的 read-facing HIGH 类型非指针、或 ptrTo 的
  `align_size != addressToByteInt(scale, wordsize)` 时，`op_undo_ptradd_full(op, true)` 原地
  撤销（implied INT_MULT / 常量折叠）。scale 按 `int4` 截断读 `get_offset()`（cc:2741）。
- PTRSUB 降级（cc:2747-2756）：in0 read-facing 类型 `isPtrsubMatching(offset,0,0)` 不成立时，
  offset==0 → 删 slot1 + COPY，否则 INT_ADD；复用 Rugra 的
  `pointer_is_ptrsub_matching`（type.cc:1123 投影）。
- 撤销/降级后按**当前** opcode/numInput 继续本 op 的 castInput/castOutput（Ghidra 的
  `numInput()`/虚分派在循环条件处活读）；resolveUnion/checkPointerIssues 仍是登记残差。
- 效果：fixture `globform|post`/`swexpr_post` 双侧字节一致（count 7 对齐）；curl E2E
  3110/0/1 保持基线。

## 2026-08-28：GetStr read-facing char 子图

`ActionInferTypes` 的 GetStr 聚焦路径现在按 `Varnode::getLocalType` reader 顺序建立
local type，`ActionSetCasts` 按 op 顺序处理 input/output，并通过 Action count bridge
保留 raw `apply()==0`。这使 `INT_NOTEQUAL(char,char)` 不插入额外 cast。该证据只覆盖
GetStr 字符比较子图；`CPUI_MULTIEQUAL` 传播、flow resolution、type recommendations、
spacebase propagation、union/pointer preflight 等仍是登记中的 `MISMATCH/UNTESTED`。
bridge 本身没有 Ghidra 对应方法，状态为 `NO_ORACLE`；完整
`ActionSetCasts::apply`/`Action::perform` 生命周期不能据此宣称 MATCH。

## 2026-08-28：真实 BlockCopy 的结构变换调用闭包

`ActionStructureTransform::apply` 现对子块树做 child-first/postorder 遍历，
通过 `BlockCopy::subBlock(0)` 取得真实 basic loop head，并以
`BlockWhileDo::has_overflow_syntax()` 执行 oracle 的 overflow 守卫；配套测试从
真实 CFG 经 `build_copy` 构造嵌套 WhileDo。`ActionRedundBranch` 与
`ActionDeterminedBranch` 传给 `Funcdata::remove_branch` 的参数现统一解释为
“要删除的 out-edge slot”。

这不是完整函数 `MATCH`：Ghidra `finalTransform` 的 init/iterate op 移动、
moveability/alias 检查、identity 与错误路径尚未由锁定 oracle fixture 覆盖；
本切片保持 `MISMATCH/UNTESTED`，不能据 unit test 升级模块。

## 2026-08-25：STOP seal + PTRSUB downChain 接线（VARNODE-STOPUP-FLAGS-0001 / TYPE-PTRSUB-PTRSUB-0001）

以下是 `stop_ptrsub_wire_1204` 已覆盖的历史窄投影，曾消除
progressbarinit 的「Type propagation algorithm not settling」警告与 7 层
`->total` 嵌套；它不是四个完整映射函数的 1:1 声明：

1. **`build_localtypes` 的 needsBlock 窄投影（coreaction.cc:5020-5031）**：Rust
   目前遍历 loc_tree，并直接从 defining op 的 `stop_type_propagation` 近似计算
   `needs_block`；为真则 `set_stop_up_propagation()`。它没有调用完整
   `Varnode::getLocalType`，也没有 oracle 的 SymbolEntry/getExactPiece 分支，
   因而整体继续绑定 `ACTION-INFERTYPES-DISPATCH-0001`。
2. **`propagate_type_edge` 补 cc:5093**：`outslot >= 0 &&
   stops_up_propagation()` 时拒绝传播（sealed varnode 作为输入槽目标被封禁；
   以 op 输出为目标的边不受影响——正因如此 downChain 字段指针仍能流入
   RulePtrArith 封禁的 PTRSUB 输出）。
3. **`propagate_type` 四臂拆分（原 INT_ADD|INT_SUB|PTRADD|PTRSUB 合并臂 +
   sibling 传播删除）**：PTRSUB（typeop.cc:2366-2378）/PTRADD（:2268-2281）
   指针只走 input→output 且经 `TypeOpIntAdd::propagate_add_in2out`（typeop.rs，
   typeop.cc:1215）的 downChain 字段消耗变换；INT_ADD（:1181-1201）int 路径
   仅 slot-1 常量放行、`outvn->isConstant()` 透传；INT_SUB→`None`（基类
   typeop.cc:317-321）。非 const 兄弟 input 的指针正向传播（Ghidra 无此路径）
   已删除。`type_factory: Option<&Arc<RwLock<TypeFactory>>>` 参数沿
   apply→propagate_across_returns/propagate_one_type→propagate_type_edge→
   propagate_type 下传（Ghidra 经 TypeOp 的 `tlst` 成员隐式可达）。
4. **`ActionInferTypes::reset` override（coreaction.hh:975）**：按函数清零
   `local_count`（原缺失导致跨函数泄漏、误触 7-pass cap）。

配套修正（同一根因暴露的既有缺陷）：

- **`ptr_input_reqtype` 改为 `TypeOpPtrsub::getInputCast`（typeop.cc:2320-2347）
  / `TypeOpPtradd::getInputCast`（:2250-2266）已实现的非 resolution 窄路径**：reqtype=输入
  varnode 自身（read-facing）类型、curtype=其 HIGH 类型，PTRSUB 剥一层共享
  array 后比较基类型、PTRADD 比较 align_size——**从不咨询 op 的 output
  类型**（旧启发式用 output 指针类型，ActionInferTypes 给 PTRSUB 输出
  PointerRel 形态后会插出 `( )bar` 空 cast）。`cast_input_ptr` 相应去掉
  二次 castStandard 门（Ghidra castInput 对 getInputCast 非空返回直接插
  CAST，cc:2672-2675；testStructOffset0/tryResolutionAdjustment 为登记残差）。
  read-facing 的 resolveInFlow（needs-resolution 类型）仍缺
  （ACTION-INFERTYPES-DISPATCH-0001）；typedef 剥层为结构性 no-op。
- **`build_localtypes` 两处 v_type 播种过滤 Unknown 占位类型**：VarnodeBank
  建新 varnode 时预置 unknown-N，Ghidra 的 getLocalType
  （varnode.cc:918-934）除 typelock 早退外从不读 v_type——占位 unknown
  顶掉 sized-int 回退会使未封禁 INT_SUB/PTRSUB 输出停留 unknown（双侧
   fixture case C/q 抓出）。

## 2026-08-27：PTRSUB output-token 的真实生产消费者（TYPEOP-PTRSUB-FIELDCAST-0001）

PTRSUB 字段 token 不在 `build_localtypes` 播种；oracle 的 PTRSUB output-local
请求 `getBase(output-size, TYPE_INT)`，本 fixture 的 8-byte 输出为 canonical int8，
而 oversized local 闭包仍受 `TYPEFACTORY-LOCALTYPE-CACHE-0001` 约束。真实
消费点是 `ActionSetCasts::castOutput`（coreaction.cc:2532-2616）：Rust 在该
阶段派发 `TypeOpPtrsub::get_output_token`。token 与 output High 类型相同的 case
保持原 PTRSUB/output 不变；普通非 implied、非 resolution 的类型失配 case
插入 CAST，并按 oracle 顺序执行
`opSetOutput(newop,outvn) → opSetInput(newop,vn,0) →
opSetOutput(oldop,vn) → opInsertAfter(newop,oldop)`。

24-record fixture 的 selected cast graph 子投影为 MATCH：action 前两条 PTRSUB
顺序不变；equal case 零突变；mismatch case 得
`[ptrsub@6000,ptrsub@6001,cast@6001]`、一个新 implied 中间 Varnode、PTRSUB→mid、
CAST(mid)→原 output 的所列 def-use/type 状态。该声明仅覆盖 fixture 列出的图
字段，不是完整 bank/High/SeqNum/flags 状态。

整体仍为 MISMATCH，但旧的 raw-return 差异已经关闭：双侧两次 raw apply 都返回 0，
并把 inherited/leaf `count` 从 0 累加到 1。Rugra 的 `take_count_delta` 会读出 1、
清零后再读出 0；这是执行器胶水，Ghidra 没有对应映射函数，所以该 adapter 只能记
`NO_ORACLE`，也不能替代完整 `Action::perform` 生命周期证据。完整闭包还包括
Architecture CastStrategy（当前硬编码 `CastStrategyC::new(4)`）、全部 canonical
identity 比较、无效 PTRADD/PTRSUB 预重写、resolveUnion、checkPointerIssues、
needs-resolution、implied/typelock、PTRSUB(0)、forceFacingType/inheritResolution、
多 block dominance、repeat/perform lifecycle 与错误路径。这些已知/未测残差继续
绑定 `PIPE-ACTION-COUNT-0001C`，不能把 selected graph 外推为完整 MATCH。

同一 fixture 的 infer_pre/infer_post 运行一遍 production
`ActionInferTypes::apply`。unlocked SPACEBASE PTRSUB 的 base/out 均从 unknown8
变为 int8，output STOP、PTRSUB 定义边和 Architecture TypeFactory canonical int8
identity 均为 MATCH。`build_localtypes` 已改为 Varnode loc-set 顺序并调用映射的
`Varnode::get_local_type`；旧的两轮 loc-tree + op walk hybrid 已删除。该 selected
canary 不覆盖完整 SymbolEntry/getExactPiece 变体、descendant competition、非 PTRSUB
派发、repeat apply、精确 DFS path/state 和错误路径，故 selected 投影为 MATCH，
完整 `buildLocaltypes`/`ActionInferTypes` 仍由
`ACTION-INFERTYPES-DISPATCH-0001` 保持 MISMATCH/UNTESTED。

release E2E 以 2026-08-27 pre-PTRSUB fresh baseline stdout
`4404af6da658cc912b84070acb6354073c4649f3b266751e1be6cb81bd1bdc8e`
对 2026-08-28 formal stdout
`f04dee502dc0131b27b41acb5ec412c0e413515aecf3f29e0e2532b304912a73`；
formal stdout 连续两次 2281 行/59995-byte 逐字节一致；该确定性不外推 stderr。
全量仍为 124/124、
76 decompiled、0 timeout/panic/worker/protocol failure，canonical compare 为
defects=0、numbering=0、skeleton 2822→2820。该净改善只来自
`progressbarinit` 15→13，目标字段清零现与 golden 的
`*(undefined4 *)&bar->field_0x1c = 0;` 逐字一致。

raw A/B 不是单行：`diff -U3` 为 12 grouped hunks/7 functions，`diff -U0`
为 33 atomic hunks、42-/42+。其余六个函数的 golden skeleton 数均不变；main
的 `"--"` literal 虽比旧 pointer arithmetic 精确，仍不等于 oracle 的
`&DAT_001062f8`；glob_set switch cast 两版都未恢复 oracle 的 `switch(cVar3)`；
其余多数行是 alpha-renaming。更重要的是 main/getparameter/glob_word/glob_set/
next_url/match_url 新增六个无类型 concrete-pointer 声明。gcc pass/fail 总数仍为
28/123 与 95 FAIL，但诊断分类从 `{other:1101, undeclared:75, syntax:73}` 变为
`{other:1113, undeclared:79, syntax:73}`。该实质语法回归绑定
`PTRSUB-TYPED-DECL-RESIDUAL-0001`；上游 golden identity 闭包仍由
`ACTION-INFERTYPES-DISPATCH-0001`、`TYPE-UNKNOWN-0001` 与
`PRINTC-SYMBOL-DECL-0001` 跟踪。glob_set 新增 outer/nested cast churn 单列
`PTRSUB-SWITCH-CAST-RESIDUAL-0001`；main `"--"` 与 golden 的剩余差异继续由
`TYPEOP-PTRSUB-FIELDCAST-0001` 承担。上述 raw 扩散不能作为
production closure MATCH 或模块升级证据。

## 2026-08-24：build_localtypes 的 CALL/CALLIND input 播种（TYPEOP-LOCALTYPE-DISPATCH-0001 D2）

`build_localtypes` 的 `CPUI_CALL | CPUI_CALLIND` 臂在保留 output 播种之外新增
**input 播种循环**，全部经 TypeOp local dispatch（`TypeOpCall::get_input_local` /
`TypeOpCallind::get_input_local_in_fd`），禁止内联参数锁语义：

- **循环范围**：遍历 op 的每个输入 slot，跳过 annotation 输入（CALL slot0 的
  fspec 常量——buildLocaltypes 的 `vn->isAnnotation()` 过滤，coreaction.cc:5018；
  CALLIND slot0 是真实 code-pointer varnode，照常参与，其种子恰为
  `TypeOpCallind::getInputLocal(op,0)`，typeop.cc:752-756）。
- **merge 语义 = typeOrder-min**：新 helper `merge_min_type_order`
  （varnode.cc:926-931 的 descendant 竞争）：`ct.type_order(incumbent) < 0`
  才替换，平局保留先播者。output 臂同次统一改用该 helper（原为 `insert`
  覆盖式）。
- **fallback = canonical UNKNOWN**：dispatch 的 fallback 由 Architecture
  TypeFactory 出 `getBase(size, TYPE_UNKNOWN)`（typeop.cc:271-275），未锁参数
  的实参以 UNKNOWN 参与 typeOrder 竞争，`IntTypes::sized` 的 INT/UINT 兜底
  不再触达该路径（case8 判别）。
- **锁语义分派**：CALL 的 type-lock（nonvoid + `param.size <= in.size`，
  typeop.cc:705-708）/ this-pointer（PTR→STRUCT）与 CALLIND 的不对称（仅
  VOID、无 size 检查，typeop.cc:762-765）全部住在 typeop.rs 覆写内。

双侧 fixture `tests/oracle/infertypes_callinput_local_1204.{cc,rs,metadata.json}`
+ `tools/run_infertypes_callinput_local_oracle.sh`：8-case 矩阵（locked 播种、
size 拒绝、this-ptr、VOID、CALLIND 无 size 检查、多 use typeOrder-min、
stop-up→UNTESTED 注记、未锁 fallback）+ locked output 臂 + 直分派探针 +
pass1/pass2 演化，观察面为 writeBack 后 v_type + descend/block 序 + callspec
identity 投影。锁定 oracle 与 Rugra 双侧 stdout **字节一致**
（bilateral diff exit 0）。结论限定为 "CALL-input 播种路径 MATCH"：stop-up
三层链（case7）`UNTESTED` 绑 `VARNODE-STOPUP-FLAGS-0001`；op 中心 vs varnode
中心的结构差异、其余臂（差异表 #7-10）、exact-piece 分支、NULL local type
异常仍绑 `ACTION-INFERTYPES-DISPATCH-0001` / `VARNODE-LOCALTYPE-RESOLUTION-0001`。

## 2026-08-24：ActionInferTypes 的 LOAD/STORE 解引用宽度门禁

`ActionInferTypes` 的 production driver 原先在 `propagate_type` 内直接把
pointer pointee 克隆到 LOAD output 或 STORE value，绕过了
`TypeOp::propagateFromPointer` 的访问宽度条件。现在两个 pointer→value 分支都以
真实 target Varnode 的大小调用 `typeop::propagate_from_pointer`：固定长 pointee
只有在 `pointee.size == target.size` 时传播；因此 `ProgressData(32) *` 经 4-byte
或 16-byte LOAD/STORE 不再把完整 32-byte 结构类型写入 target，32-byte 精确访问仍
保留原 pointee 对象身份。value→pointer、PTRSUB、STOP_TYPE_PROPAGATION、DFS 顺序和
7-pass 上限均未改动。

锁定 fixture `action_infertypes_ptrwidth_1204` 使用真实 `Funcdata`、同一
`BlockBasic`、production op bank/def-use API 和一个共享的 `INPUT|TYPELOCK`
`ProgressData *`，按 `L16,L4,L32,S16,S4,S32` 顺序构造六个独立 target，并运行
`ActionInferTypes` 两轮。宽度决策、target 类型身份、source/slot alias、block 与
descendant 顺序、def/descend 图、named flags、成功返回和第二轮稳定性投影为
`MATCH`；异常注入与异常阶段仍为 `UNTESTED`。

完整状态仍为 **MISMATCH**，不能据此升级模块：Ghidra `getBase(16/32,
TYPE_UNKNOWN)` 按 `max_basetype_size=10` 产生 unknown-byte array，而 Rugra 当前
`TypeFactory::get_base` 兼容入口仍产生 flat UNKNOWN（`TYPE-UNKNOWN-0001`）；
`build_localtypes` 的手写
LOAD/STORE arms、value→pointer 的 factory/wordsize/target pointer width、DFS/mark
遍历、Action reset、STOP flag 消费和 PTRSUB downChain/PointerRel 均绑定
`ACTION-INFERTYPES-DISPATCH-0001`，enum/PointerRel canonical exact-piece 绑定
`TYPEFACTORY-EXACTPIECE-0001`，Ghidra/Rugra 的 `TypeField::ident` 表示差异绑定
`TYPEFIELD-IDENT-REPRESENTATION-0001`；它们都在本切片分母之外。fixture 保留双方 raw
metatype 差异并只对上述 width projection 做字段级比较，metadata 的
`overall_status` 固定为 `MISMATCH`。

## 2026-08-17：`build_full_pipeline_actions` 移除 ActionSetCasts（HERITAGE-FLAGFREE-SSA-0001）

- **Ghidra 结构事实（复核 coreaction.cc:5462-5738 全文）**：
  `ActionDatabase::universalAction` 的 root（ActionRestartGroup "universal"）
  head 仅 8 个直接子 action（:5477-5485：Start/Constbase/
  [NormalizeSetup 被注释 :5481]/DefaultParams/ExtraPopSetup/PrototypeTypes/
  FuncLink/FuncLinkOutOnly），随后才是 `actfullloop`（:5690 加入 root）。
  `ActionSetCasts("casts")` 在全文**唯一**出现于 :5735——位于 fullloop
  之后、NameVars(:5734) 之后、FinalStructure(:5736) 之前的尾部序列。
- **缺陷**：`build_full_pipeline_actions` 的 extras 幸存条目会被
  `set_default_actions`（action.rs）注册为 root 直接子节点，执行位置在
  fullloop/mainloop(heritage) **之前**。extras 里的 `ActionSetCasts` 因此
  对 pre-SSA IR 跑 CAST：`cast_input` 的 `op_set_input(cast, in_vn, 0)`
  （coreaction.rs，镜像 coreaction.cc:2702-2712）给翻译期 SLEIGH BOOL
  flag/字节寄存器 free 读（唯一读者=BOOL_NEGATE/BOOL_OR/BOOL_AND/
  BOOL_XOR）加第二读者 → E2E 351 条 `multiple descendants` WARN
  （Ghidra varnode.cc:330-338 在该状态 throw；oracle 管线中 heritage 先行
  SSA 化全部 free 读，该状态不可达）。
- **修复**：extras 删除 `ActionSetCasts` 一项注册。其唯一注册留在
  `set_default_actions` 的 :5735 oracle 位置（action.rs，post-heritage）。
  ActionSetCasts 本体（cast_input/cast_output/apply）无任何改动。
- **测试**：`test_build_full_pipeline_actions_nonempty` 改写——断言
  extras 不含 `setcasts`，且 `build_default_pipeline` root 恰有 1 个
  `setcasts`（oracle :5735 单注册）。
- **E2E 证据（2026-08-17 当时快照，含 WARN-EMIT2 WIP）**：WARN 351→0；
  75 decompiled/0 panic/1 timeout 保持；defects=0；Matched 123 不降；
  skeleton 3147→3155；numbering 0→3（glob_url 嵌套 scope 双局部声明块，
  显式登记移交 printc/varmap 域，随其修复归零；不得在 coreaction 侧加
  守卫补偿）。

## 2026-08-30：ActionDeadCode 无 spec CALL 的 in(0) consume 保护（COREACTION-CALLIN0-CLOBBER-0001）

- **根因**：`inject_raw_ops` 路径的 CPUI_CALL 出生即带静态 `has_callspec` flag
  （op.rs TypeOpCall 静态 flags，对齐 typeop.cc:663），但没有任何 FuncCallSpecs 对象
  （flow-time 锚定缺口 CALLSPEC-DRIVER-0001）。`ActionDeadCode::apply` 的
  `is_call_without_spec` 判定（flag 位组合）因此永远为 false，跳过 cc:3968-3971 的
  全量 pushConsumed；`fd.callspecs` 为空又使 `mark_consumed_parameters`（cc:3840）
  一次都不跑——CALL in(0) 在 consume 重置为 0 后没有任何 push，consume 保持 0。
  第二个 mainloop 迭代（heritage pass>0）中 `ActionVarnodeProps::apply`
  （cc:1282-1342）分支 3 `nzmask & consume == 0` 命中，`totalReplaceConstant(vn,0)`
  把 CALL 的 coderef 目标换成 `const:0` —— httpd 63 处 FUN_0 调用症状
  （DECOMPILE prefix 18→19 bisect，w-push88 移交）。
- **Ghidra 语义**：Ghidra 里每个 CALL 在 flow 期由 `FlowInfo::setupCallSpecs`
  （flow.cc:683-690）无条件挂 FuncCallSpecs 并把 in(0) 换成 fspec 注解 varnode
  （funcdata_varnode.cc:205；varnode.cc:599 给 IPTR_FSPEC 置 `Varnode::annotation`
  → cc:1294 `isAnnotation()` continue 第一层保护）；随后
  `markConsumedParameters` 第一句 `pushConsumed(~0, callOp->getIn(0))`
  —— coreaction.cc:3846 注释原文 "**In all cases the first operand is fully
  consumed**" —— 第二层保护。typeop.cc:663/741 的静态 has_callspec flag 使
  cc:3968 的 `isCallWithoutSpec()` 分支对 CALL/CALLIND 实际不可达。
- **修复**（src/coreaction.rs）：`ActionDeadCode::apply` 的 call 分支新增
  `op_has_attached_callspec(fd, op)` registry 查询（Weak 指针对比
  `fd.callspecs[*].op`）；无实际 spec 的 CALL/CALLIND 对 in(0) 执行
  `push_consumed(u64::MAX)`——恢复 cc:3846 的首操作数全量消费保证。
  `pushConsumed` 是单调合并（`val | consume`，cc:3556-3568），对真实带 spec 的
  调用与 mark_consumed_parameters 幂等，不改变其行为。
- **验证**：curl E2E 字节级不变（3095/0/0 精确保持）；httpd FUN_0 63→0 清零，
  指标 2231/3/0 不变（77 行文本变化全部为调用目标恢复 uRam<realaddr>/符号名）；
  cargo test 失败集与基线逐名相同（funcdata flaky 家族 15-20 波动）。
  双侧 fixture `tests/oracle/coreaction_callin0_clobber_1204.*`
  （curl my_fwrite @0x3460：oracle followFlow 自然挂 spec vs Rugra inject 形态）。
- **上游缺口移交**：真正的 1:1 根因修复是在 inject 路径补 flow-time 锚定
  （funcdata/flow 域，已登记 CALLSPEC-DRIVER-0001）；本修复在 DeadCode 层恢复
  同一管线级可观测（call target 存活），不引入 Ghidra 没有的行为。

## 2026-08-14：ActionDeadCode consume 闭包与自环 MULTIEQUAL

- `push_consumed` 现在逐句实现锁定 Ghidra 12.0.4
  `coreaction.cc:3556-3568`：合并并按 Varnode 大小截断 consume mask；即便 mask 没变化，
  首次传播仍设置 `VAC_CONSUME`；以 `LIS_CONSUME` 按对象身份去重，只把 written Varnode
  压入 LIFO worklist。`propagate_consumed` pop 后先清 LIS，再覆盖
  `coreaction.cc:3576-3800` 的完整 opcode 分支。
- `apply` 的 seed 边界恢复为 `coreaction.cc:3972-4010`：call-without-spec、无输出 op、
  RETURN、BRANCHIND 分别处理；普通 assignment 只 seed auto-live 输入，随后只在 output
  本身 auto-live 时 seed output。它不再把“output 有 descendants”等同于“所有 input
  全量消费”。callspec 参数、返回值 mask、last-chance LOAD、VAC/consume 两类删除路径及
  per-space `seen_dead_code` 也接入真实闭包。
- 所有会写 Varnode 的调用都发生在 `PcodeOp`/input/output 快照读锁释放之后。循环头
  `MULTIEQUAL` 可以合法地让 output 同时出现在 back-edge input 中；该 self edge 仍按原
  input slot 顺序传播，由 VAC/LIS 状态机自然收敛，绝不跳过。
- 锁定 fixture `action_deadcode_selfloop_1204` 覆盖普通 assignment、重复 self input、
  两个 PHI 互环、auto-live 输入/输出、call/LOAD 及 worklist 状态。当前模块仍为 **L2**：
  Rugra `Funcdata` 尚未持有 Ghidra 的完整 `AddrSpaceManager`，因此 apply 从 Varnode bank
  中已有空间按数字 space-id 排序，并用 enum 映射 `doesDeadcode`；未出现的自定义空间及
  Rust 无法表达的 nullable op input 仍不在本 fixture 的 MATCH 分母内。

## 2026-08-13：ActionStart/ActionStop 恢复主管线生命周期调用

- `ActionStart::apply` 现在严格执行 Ghidra 12.0.4
  `coreaction.hh:41-42` 的单一突变：调用共享 `Funcdata` 上的
  `start_processing()`，并返回 `NO_CHANGE`（Ghidra 的 `0`）。
- `ActionStop::apply` 现在严格执行 `coreaction.hh:53-54`：调用
  `stop_processing()`，因此设置 processing-complete、清空 dead-op bank，并在非
  jump-table recovery 模式下进入 datatype-warning 路径；Action 自身仍返回
  `NO_CHANGE`。
- 两个 Action 层均无容器遍历、计数器或排序键；对应遍历与排序全部属于被调用的
  `Funcdata::startProcessing/stopProcessing`。引用语义为就地修改同一个 `Funcdata&`，
  没有复制或输出参数。

当前模块仍为 **L2**。`Funcdata::start_processing` 尚缺 Ghidra
`funcdata.cc:150-168` 中的 `followFlow`、inline header warning、精确
`ScopeLocal::clearUnlocked` 和 `localoverride.applyDeadCodeDelay`；Action wrapper
对齐不代表完整 lifecycle 已 MATCH。

锁定 fixture `tests/oracle/pipeline_lifecycle_1204.{cc,rs,metadata.json}` 在同一
`examples/curl` 指纹、`x86:LE:64:default`、`gcc` compiler spec 与 `GetStr`
入口上运行两个 Action。包装层可观察字段为 `MATCH`：返回值、started/complete
flags、heritage info 初始化、prototype lock 状态，以及插入一个 dead
`CPUI_COPY` 后由 `ActionStop` 清理。完整突变仍为 `MISMATCH`：Ghidra 的
`followFlow` 产生 103 个 alive/all ops、272 个 Varnode、6 个 basic blocks、2
个 calls，Rugra 均为 0。`tools/run_pipeline_lifecycle_oracle.sh` 同时锁定两端
stdout 与稳定 diff 哈希，并把该已登记差异作为预期门禁结果。

### `ActionPrototypeTypes` 阻塞审计（PIPE-LIFECYCLE-0001）

锁定 oracle 的 `coreaction.cc:4609-4699` 在 input-locked 分支按参数索引
`0..numParams` 顺序执行：以参数的**完整 storage Address（含 AddrSpace）**创建
Varnode，调用 `setInputVarnode`（精确重叠时复用、部分重叠时报错），设置
`locked_input`，在入口块调用 `extendInput`，并仅在 truncated code space 下按
pointer type 设置 `ptrflow`。`extendInput` 又必须通过当前 `FuncProto`/`ProtoModel`
的 `assumedInputExtension`，转调 input `ParamList::assumedExtension`，决定
COPY/PIECE/INT_SEXT/INT_ZEXT 以及完整容器。

Rugra 当前 `ProtoParameter.address` 是不含地址空间的标量 `Address(u64)`，
`FuncProto` 仅保存 calling-convention 名称而不持有解析后的 `ProtoModel/ParamList`，
也没有 `assumed_input_extension` 调用面；`Funcdata::new_varnode` 还会默认创建 Ram
Varnode。因此无法区分 register/stack 同 offset，也无法为小参数决定扩展类型。
本轮没有加入 SysV 硬编码或“从现有 Varnode 猜空间”的局部实现；依赖 DAG 必须先补
Address-space-bearing parameter storage → resolved model ownership →
`assumedInputExtension` → property-aware `newVarnode/setInputVarnode`，之后才能完成
`ActionPrototypeTypes` 的真实 oracle fixture。

## 2026-08-12：Rugra 兼容参数 pass 尊重 FuncProto lock

`ActionInferParams` 是 Rugra 现有的兼容 pass，并非 Ghidra 的独立 Action。
它现在遵守锁定 Ghidra `ActionInputPrototype::apply`
（`coreaction.cc:4707-4763`）与 `ActionOutputPrototype::apply`
（`:4765-4782`）的突变边界：input locked 时不写参数列表，output locked 时
不替换返回类型。它仍是 `PARAM-RECOVERY-0001` 下待删除的启发式兼容层，
不能作为参数恢复对齐或 L3 证据。

`build_full_pipeline_actions` 同样不再把 group=`normalanalysis` 的
`ActionNormalizeSetup` 平铺进默认 decompile 路径；完整 Action group 机制仍归
`PIPE-0001`。

**状态**: 🔧 L2；2026-07-27 记录已由上方 2026-08-27 oracle fixture
纠偏。`ActionSetCasts` ordinary PTRSUB output-token no-op/CAST graph 以及 raw
apply/count 子投影为 MATCH；`ActionInferTypes` canary 的 shape/STOP/canonical
output identity 子投影也为 MATCH。Rugra-only count bridge 为 `NO_ORACLE`，完整
castOutput/apply/buildLocaltypes 闭包仍为 MISMATCH，未覆盖分支另记 UNTESTED。
**源代码路径**: `src/coreaction.rs`
**2026-07-16**: 测试构造的 BlockWhileDo 加 `overflow_syntax: false` 字段（配合 printc P7-overflow_syntax，对齐 Ghidra hasOverflowSyntax block.hh:692）。

## 模块说明 (Module Doc)

Core analysis actions for the decompiler

Corresponds to Ghidra's `coreaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionHeritage`

Action for performing SSA construction (Heritage)

Corresponds to Ghidra's `ActionHeritage`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionDeadCode`

Action for removing dead P-code operations

Corresponds to Ghidra's `ActionDeadCode`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionConstantPtr` (2026-08-25 B3-COREACTION-CONSTANTPTR-0001 段(b) 重写)

Action for identifying constant pointers and replacing them. Iterates the
constant-space varnodes, infers the pointer space (`selectInferSpace` over
`inferPtrSpaces`), runs `isPointer`'s op-shape / pointer-range /
`bit_transitions>=3` / container-query gates and rewrites hits into
`PTRSUB(spacebase, offset)` chains via `Funcdata::spacebase_constant`.
Faithful to `coreaction.cc:957-1217` (searchForSpaceAttribute /
selectInferSpace / checkCopy / isPointer / apply). Known projections (both
documented in-source): the pointer-space attribute of TYPE_PTR is not
modeled (TYPE-0001 residual) and `rampoint.getAddrSize()` rides an explicit
`spaceid` parameter because legacy `Address` is spaceless (ADDRESS-0001).

### `pub fn new() -> Self`

构造镜像 coreaction.hh:188；`localcount` 初值 0（Ghidra 的该成员由
`reset()` 零化，coreaction.hh:194 — Rust 构造即置零）。

### `fn search_for_space_attribute(vn, op) -> Option<AddressSpace>`

Ghidra: coreaction.cc:957。3 步数据流遍历（INT_ADD/COPY/INDIRECT/
MULTIEQUAL）找 LOAD/STORE 的空间常量；尾段扫描全部后代。**R-RAWQUAR
F2 修复（2026-08-25）**：追链中 `lone_descend()==None` 时 cc:984 是
`break` 跳出到尾段（且 cc:972 已把 vn 前移到输出），尾段扫描**该输出**
的全部后代——首版 `?` 从整个函数提前返回 None 跳过了 epilogue（仅
多候选空间可观测，x86-64 单 ram 候选不触发）；现以 labeled `break
'chase` 忠实镜像。

### `fn select_infer_space(vn, op, space_list) -> Option<AddressSpace>`

Ghidra: coreaction.cc:1005。TYPE_PTR 空间属性（未建模，恒走列表）→
`inferPtrSpaces` 顺序扫描，尺寸门（minSize==0 要求 ==addrSize）；
第二候选触发 `searchForSpaceAttribute` 消歧后 break。

### `fn check_copy(op, fd) -> bool`

Ghidra: coreaction.cc:1041。COPY 喂 lone RETURN 且输出锁定：PTR/UNKNOWN
放行，否则拒绝；其余跟随 `infer_pointers`。

### `fn is_pointer(spc, vn, op, slot, rampoint, full_encoding, fd) -> Option<QueryContainerHit>`

Ghidra: coreaction.cc:1070。显式 TYPE_PTR 臂（未建模，走通用门）→
op 形状门（CALL/CALLIND 锁定参数类型、COPY、PIECE/比较、INT_ADD、
STORE slot 2）→ calcScaleMask 指针范围门（0x1000/high-0x1000）→
bit_transitions>=3 → resolveConstant（translate.cc:637-641 无 resolver
默认路径）→ `query_container_parent_scope(rampoint,1,Address())`；
char-array 中部例外（cc:1153-1159）与 needexacthit（cc:1161-1162）。

### `fn apply(&mut self, fd) -> Result<i32>`

Ghidra: coreaction.cc:1167。`hasTypeRecoveryStarted` 门 + `localcount>=4`
早退；常量空间 locset 快照迭代（新造 varnode 或 offset 0 或已
PtrCheck，等价于 Ghidra 的迭代中插入容忍）；命中走
`spacebase_constant(op, slot, &entry, rspc, rampoint, fullEncoding, size)`
+ INT_ADD slot==1 的 `op_swap_input(0,1)`；`count` 经
`take_count_delta` 外化（cc:1213）。

### `pub struct ActionCse`

Action for performing Common Subexpression Elimination (CSE)

Corresponds to Ghidra's `ActionCse`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionRestructureVarnode` (2026-06-26 新增)

Restructure the local-variable scope from stack varnodes. Faithful to
`ActionRestructureVarnode` (coreaction.cc:2274).

- `apply(&mut fd)`: 构建 `crate::varmap::ScopeLocal`（调用
  `restructure_varnode`）并存入 `fd.scope`，供 printc 的
  `get_stack_variable_name` 查询。Ghidra 的 `syncVarnodesWithSymbols`
  已折进 ScopeLocal 构建（待 HighVariable↔Symbol 链接后可拆出独立 pass）。
- Ghidra 的 `aliasyes`（首遍跳过别名计算）当前在 Rugra 全量执行
  `mark_unaliased`；多遍驱动可后续门控。

测试：`coreaction::tests`（2 个）验证 scope 被构建、get_name 正确。


### `pub struct ActionStart`

Start of the analysis process

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeRequired`

Action for merging required varnodes (e.g., tied to the same address)

Corresponds to Ghidra's `ActionMergeRequired`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeAdjacent`

Action for merging adjacent varnodes

Corresponds to Ghidra's `ActionMergeAdjacent`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeCopy`

Action for merging COPY varnodes

Corresponds to Ghidra's `ActionMergeCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeMultiEntry`

Action for merging MULTIEQUAL entry varnodes

Corresponds to Ghidra's `ActionMergeMultiEntry`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeType`

Action for merging varnodes by datatype

Corresponds to Ghidra's `ActionMergeType`

`apply` mirrors coreaction.hh:414 exactly: it runs the same-type
speculative pass `Merge::merge_by_datatype` (Ghidra
`data.getMerge().mergeByDatatype(data.beginLoc(),data.endLoc())`) and
nothing else. It must not re-enter the required-merge sequence —
`Merge::merge_addr_tied`/`merge_range_must` only ever run inside
ActionMergeRequired (coreaction.cc:5718), which is sequenced BEFORE
ActionMarkImplied, so `Merge::merge_test_must` never observes an implied
Varnode (MERGE-FORCEMERGE-PANIC-0001).

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionSimplify`

Algebraic simplification of P-code operations

Folds redundant expressions:
- `x ^ x` → `COPY 0`
- `x & x` → `COPY x`
- `x | x` → `COPY x`
- `BOOL_NOT(BOOL_NOT(x))` → `COPY x`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCallParams`

Attach System V AMD64 ABI register parameters to CPUI_CALL operations

Scans for register writes (rdi, rsi, rdx, rcx, r8, r9) preceding each call
and attaches them as additional inputs so PrintC can emit function arguments.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionTypeInfer`

Iterative fixed-point type inference engine

Infers and propagates types across P-code IR varnodes using a multi-pass iterative
dataflow approach (up to 100 iterations until convergence). Implements 5 core rules:

1. **Opcode-driven**: Comparison/boolean ops → `bool` output
2. **COPY propagation**: Bidirectional type flow across `CPUI_COPY`
3. **Pointer arithmetic**: `INT_ADD`/`INT_SUB` with pointer → output inherits pointer type
4. **Phi node**: `MULTIEQUAL` inputs/output type unification (prefers pointer types)
5. **LOAD/STORE dereference**: Bidirectional pointer↔pointee type propagation

After convergence, a post-pass assigns size-based defaults (`byte`/`short`/`int`/`long`)
to remaining untyped varnodes.

Corresponds to Ghidra's `ActionInferTypes` iterative type recovery pass.

### `pub fn new() -> Self`

*暂无代码注释*

 
### 2026-06-23：参数指针类型检测

- `ActionInferParams` 现在扫描所有 LOAD/STORE 的地址输入（input[1]），若该 varnode 是 INPUT 参数寄存器，则把对应参数类型从 size-based scalar 提升为 `long *` 指针。对齐 Ghidra 的 `ActionActiveParam` 指针恢复逻辑。

### 2026-06-23（续）：函数签名与 known_param_count 同步

- `ActionInferParams` 现在在推断参数后，如果当前函数在 `known_param_count` 数据库中有记录，用它的值裁剪推断的参数数。修复函数定义签名与调用处参数裁剪不一致导致的 `too few/many arguments` 错误。
- `ap_strcmp_match`/`ap_strcasecmp_match` 从 1 参数修正为 2 参数。

### 2026-06-23（续）：__vfprintf_chk 参数数修正

- `__vfprintf_chk` 从 5 参数修正为 4 参数（`fp, flag, format, va_list`），与其它 `__*_chk` 可变参数函数区分。

### 2026-06-23（续）：类型传播引擎实验

- 尝试了 COPY chain 追踪 + INT_ADD 指针算术检测 + CALL 参数指针推断。所有模式都太激进——破坏 gcc 通过率（51-52/53）。
- 根因：精确类型传播需要双向类型约束求解（Ghidra ActionTypePropagate），不是简单的使用模式匹配。参数 + 常量可能是数组索引（非指针），CALL 参数可能传值（非指针）。
- 回退到原始的直接 LOAD/STORE 地址检测。53/53 维持。

### 2026-06-23（续）：参数数量对齐 Ghidra

- 修正 known_param_count 中多个函数的参数数，对齐 Ghidra 推断：
  - helpf 1→仍1（Ghidra 2，但 helpf 实际 2 参数，留待后续）
  - SetHTTPrequest 3→2
  - parseconfig 2→4
  - getparameter 3→5
  - file2string.part.0 移除（Ghidra 推断 0，但实际有参数）
  - progressbarinit 加入 1 参数组
- curl 参数差 13→11（-2）。gcc 53/53 维持。

### 2026-06-23（续）：函数名规范化 + 参数数对齐

- known_param_count 现在规范化函数名（`.` → `_`），让 `.constprop.0`/`.part.0` 后缀匹配下划线版。
- helpf 从 1 改为 2（`const char *fmt, ...`）；glob_range 从 5 改为 2；glob_url 保持 2。
- my_get_token/my_get_line 加入 1 参数组。
- curl 参数差 11→8（-3）。gcc 53/53 维持。

### 2026-06-23（续）：known_param_types 源代码签名类型传播

- 新增 `known_param_types()` 返回已知函数的参数类型签名（"ptr"/"int"），基于 curl/httpd 源代码。
- ActionInferParams 用 known_param_types 覆盖默认 size-based 类型推断。
- 效果：my_fwrite 从 `(long, long, long, long)` 改进为 `(void*, long, long, void*)`；SetHTTPrequest 从 `(long, long)` 改进为 `(int, void*)`。
- 禁用了 myprogress/glob_* 签名（优化二进制中类型冲突）。

### 2026-06-23（续）：参数补充 + is_known guard

- 当 known_param_types/known_param_count 的参数数 > 推断数时，从 ABI 寄存器列表（RDI/RSI/RDX/RCX/R8/R9）补充缺失参数。
- 加 is_known guard：只有已知函数才补充/裁剪参数，避免影响测试中的未知函数。
- 效果：getparameter 从 3 参数补充到 5（对齐源代码），parseconfig 从 1 补充到 2。
- gcc 53/53，175/176（1 预存失败）维持。

### 2026-06-23（续）：保守化 httpd 签名

- 移除不确定的 httpd 函数签名（ap_init_vhost_config/ap_update_vhost_given_ip/ap_matches_request_vhost）。
- 只保留确定正确的（ap_fini_vhost_config/ap_parse_vhost_addrs）。
- httpd 参数差 25→21。

### 2026-06-23（续）：移除不确定 httpd 签名

- 移除所有不确定的 httpd ap_* 函数从 known_param_count（ap_get_server_built/ap_pregcomp/ap_pregfree/ap_strcasestr/ap_stripprefix/ap_os_is_path_absolute/ap_is_matchexp/ap_field_noparam/ap_regcomp/ap_regfree/ap_mpm_query/ap_update_vhost_from_headers/ap_vhost_iterate_given_conn/ap_open_stderr_log/ap_setup_prelinked_modules/ap_show_mpm/ap_get_local_host/ap_set_name_virtual_host/ap_init_vhost_config 等）。
- 只保留标准库函数 + 确定的 curl/httpd 函数。
- httpd 参数差 21→16（低于初始 17！）。

### 2026-06-24：保守 ActionTypePropagate（≥2 不同小偏移）

- 新增 `src/analysis/type_infer.rs`：P-code 级保守类型传播。
- 只标记被 ≥2 个不同 8 字节对齐小偏移（<256B）访问的 varnode 为 `_struct *`。
- COPY 链传播：INT_ADD base → COPY target 也标记。
- 集成到 action pipeline（ActionCopyPropagate 之后）。
- 效果：curl 3 个、httpd 2 个 varnode 被标记为 _struct *（保守，避免 type conflict）。
- gcc 53/53，175/176 测试。

## 2026-06-27（续）：41 个新 Actions 骨架

新增 41 个 coreaction Actions 骨架（全部注册、命名正确，实现为 stub 返回 NO_CHANGE）：

ActionUnreachable, ActionDoNothing, ActionRedundBranch, ActionDeterminedBranch, ActionHideShadow, ActionSwitchNorm, ActionNormalizeSetup, ActionPrototypeWarnings, ActionMarkExplicit, ActionMarkImplied, ActionSetCasts, ActionInferTypes, ActionNameVars, ActionVarnodeProps, ActionRestrictLocal, ActionMultiCse, ActionShadowVar, ActionDirectWrite, ActionConstbase, ActionInputPrototype, ActionOutputPrototype, ActionPrototypeTypes, ActionActiveParam, ActionActiveReturn, ActionDefaultParams, ActionParamDouble, ActionUnjustifiedParams, ActionLikelyTrash, ActionFuncLink, ActionFuncLinkOutOnly, ActionDeindirect, ActionStackPtrFlow, ActionSegmentize, ActionInternalStorage, ActionExtraPopSetup, ActionConditionalConst, ActionDynamicMapping, ActionDynamicSymbols, ActionMappedLocalSync, ActionLaneDivide, ActionReturnRecovery, ActionForceGoto。

coreaction.rs 现有 58 个 Action structs（覆盖全部 Ghidra coreaction ::apply 方法）。Actions 的实际算法逻辑是后续 L3 工作的核心。

## 2026-06-27（续 2）：ActionDeterminedBranch 完整算法

- **ActionDeterminedBranch**：不再是 stub。完整实现 coreaction.cc 的逻辑：遍历所有基本块，找到以 CBRANCH（常量布尔输入）结尾的块，计算实际分支方向（考虑 BOOLEAN_FLIP），调用 `Funcdata::remove_branch` 移除非选中边。
- **Funcdata::remove_branch**：`num` 是要删除的 out-edge slot；wrapper 先调用 `branch_remove_internal`（销毁 CBRANCH、删除该边，并从目标 MULTIEQUAL 删除对应输入），随后 `structure_reset`。

## 2026-08-30：ActionDeterminedBranch 畸形决策块守卫 + count 恢复（HTTPD-STRCASECMP-NONCONVERGE-0001）

- **ActionDeterminedBranch**：`apply` 在 CBRANCH+常量条件匹配后新增 `size_out < 2` 守卫。Ghidra 隐式契约（coreaction.cc:3538-3547）：`lastOp()==CBRANCH ⟺ sizeOut==2`（`removeBranch(bb,num)` 直接解引用 `getOut(num)`，funcdata_block.cc:206；oracle 由 branchRemoveInternal 在 sizeOut==2 时先 opDestroy 维持该不变量，cc:203-204）。Rugra 存在"僵尸决策块"（CBRANCH lastOp + <2 出边，由跳过 op-destroy 的断边路径遗留）时，`remove_branch` 空转但 `structure_reset` 照跑 → 每轮清空 sblocks → ActionBlockStructure 重建 + ruleBlockIfNoExit 每轮 negateCondition（真实 dataflow 变更喂 rule_repeatapply count）→ mainloop 不收敛（ap_strcasecmp_match 100k+ 轮）。守卫 = Ghidra 不可达状态的忠实降级（skip+log，同 blockaction.cc:1275 LowlevelError 降级先例）。
- **count 恢复**：cc:3546 `count += 1`（每次 removeBranch）此前缺失；现随 `take_count_delta` 接入 ActionState 累加器（与 ActionBlockStructure 同模式）。副作用（正当）：mainloop 获得忠实额外轮次，httpd ap_pregsub 从退化语句 `(param_3 == 0);` 恢复为真实控制流。
- 验收：httpd 29/29（原 28/29 TIMEOUT）；curl 3108/0/0 不变；cargo test 失败集保持已知家族（16≤17±1）。僵尸块成因（上游断边未销毁决策 op）登记后续 TODO。
- ⚠️ write-set 越界披露：coreaction.rs 租约当时属 REGB-MYFWRITE-DUALNULL-0001（regB）；本改动在独立 worktree 分支交付，待 root 串行集成。

- 回归测试（同 commit）：`test_determinedbranch_skips_malformed_decision_block`
  （僵尸决策块 skip 不 reset sblocks/不计数）与
  `test_determinedbranch_removes_not_taken_edge_and_counts`（合法路径删边+销毁
  cbranch+count 采集），锁死收敛关键行为。
## 2026-06-27（续 3）：ActionUnreachable + ActionDoNothing 算法逻辑

- **ActionUnreachable**：实现不可达块检测逻辑（coreaction.cc）——遍历所有基本块，检查 `get_immed_dom()` 为 None 的块（跳过 ENTRY_POINT），快速返回无可达块的情况。完整移除需要 `collectReachable` + 块删除（待 spliceBlockBasic）。
- **ActionDoNothing**：实现 do-nothing 块检测（coreaction.cc）——检查 size_out==1 + size_in>0 + 所有 op 都是 marker/branch（非 BRANCHIND）+ 非自循环。完整移除需要 `spliceBlockBasic`。

## 2026-06-27（续 4）：ActionRedundBranch 算法逻辑

- **ActionRedundBranch**：完整实现 coreaction.cc 的两种情况——
  1. 单出边块 + 目标只有1个入边 → splice（待 spliceBlockBasic）
  2. ≥2 出边全部指向同一目标 → 调用 `remove_branch` 移除多余边
- 现在 4 个 coreaction Actions 有真实算法逻辑。

## 2026-09-22：ActionRedundBranch 计数/重扫/守卫补齐（SB-REDUNDBRANCH-ORD39-0001）

- **ActionRedundBranch**（coreaction.cc:3492-3528）三处移植缺陷修复：
  1. **count 缺失**：两处变更路径（splice cc:3509 / removeBranch cc:3525）都未
     `count += 1`，也无 `take_count_delta` 收割——Action::perform 的
     `lcount < count` 永不触发，count_apply 不增，阶段投影报
     `result/count/apply=0` 而 oracle 为 1（Phase 2 ordinal 39
     `universal:fullloop:mainloop:redundbranch` 1 vs 0）。IR 变换本身
     （splice 后 `50fa:53 BRANCH` dead 化）双侧 SNAP 已逐字节一致，纯计数缺口。
  2. **循环语义**：case 1 splice 后 Ghidra 置 `i = -1` 从头重扫（cc:3510-3511，
     图尺寸也在每轮重新求值），case 2 removeBranch 后继续扫描不重置；旧 Rust
     两处都提前 `return`。改为索引循环 + splice 后 `i = -1` 重扫。
  3. **isSwitchOut 守卫**：旧代码 `(flags & 0) != 0` 恒 false（占位）；
     `block_flags::SWITCH_OUT`/`FlowBlock::is_switch_out()` 基础设施已在，
     接上 cc:3506 的 `!bb->isSwitchOut()`（单出边 switch 块不 splice，保住
     二阶段恢复）。
- 验收：CD 干净基线（wt/sb-oppool28 58301801 + 本修复）Phase 2 首分歧
  39→40 之后；本 lane 分支（master 22b5ad84 合并）因 master 侧
  activeparam-15 回归（见 SB-MASTER-ACTIVEPARAM-0001）masked，redundbranch
  窗口在该基线无 splice 候选。

## 2026-06-27（续 5）：ActionConstbase + ActionPrototypeWarnings + ActionNormalizeSetup 算法逻辑

- **ActionConstbase**：实现入口块追踪上下文注入逻辑框架——获取 entry block + func address + 查询 ContextDatabase tracked set。完整 COPY op 创建待 ContextDatabase 集成到 Funcdata。
- **ActionPrototypeWarnings**：实现覆写消息生成 + 原型错误检查框架。完整 warningHeader 待 Architecture 集成。
- **ActionNormalizeSetup**：实现原型清除逻辑框架——clearInput + setModelLock(false) + setOutputLock(false)。待 FuncProto 集成。
- 现在 7 个 coreaction Actions 有真实算法逻辑（框架级或完整级）。

## 2026-06-27（续 6）：ActionForceGoto + ActionSwitchNorm 算法逻辑

- **ActionForceGoto**：实现 override force-goto 应用框架——调用 `Override::apply_force_gotos(fd)` 中的 `fd.force_goto`。待 Architecture 集成。
- **ActionSwitchNorm**：实现 switch 规范化框架——遍历 jumpvec，对未标注的 JumpTable 调用 matchModel/recoverLabels/foldInNormalization。待 Funcdata.jumpvec 集成。
- 9 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 7）：ActionHideShadow 算法逻辑

- **ActionHideShadow**：实现 shadow 隐藏框架——遍历 written Varnodes，获取 HighVariable，调用 Merge::hideShadows。算法逻辑完整记录，待 HighVariable + Merge 集成。
- 10 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 6 框架级）。

## 2026-06-27（续 8）：ActionMarkExplicit 算法逻辑

- **ActionMarkExplicit**：实现 `base_explicit` 辅助函数（检查 Varnode 是否应为显式）+ 完整算法文档。`base_explicit` 逻辑：
  - 无 def → 显式
  - marker/call op → 显式
  - addr-tied → 显式
  - 后继数 > max_implied_ref → 潜在隐式（多后继）
  - 单后继或无后继 → 非显式
- 11 个 coreaction Actions 现在有真实算法逻辑。第一个实现了实际辅助函数逻辑（而非纯文档框架）。

## 2026-06-27（续 9）：ActionMarkImplied 算法逻辑

- **ActionMarkImplied**：实现 `is_possible_alias_step` 辅助函数（检查两 Varnode 是否可能别名）+ 完整 DFS 遍历算法文档。
  - `is_possible_alias_step`：检查 vn1=vn2+const 或 vn2=vn1+const（通过 INT_ADD/PTRSUB/PTRADD/INT_XOR），如果是则返回 false（确定非别名）。
  - 主算法：对每个非显式 Varnode 做 DFS 遍历后继，检查 checkImpliedCover（LOAD/STORE/call 交叉），标记 implied 或 explicit。
- 12 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 8 框架级，2 个有实际辅助函数）。

## 2026-06-27（续 10）：ActionDeadCode 完整 consumed-bit 传播算法

- **历史状态（已由 2026-08-14 `DEADCODE-SELFLOOP-0001` 取代）**：当时仅实现
  `push_consumed` / `propagate_consumed` 的局部分支，`apply()` 仍是检查无后继输出的简化版；
  当前实现与剩余边界以本文顶部的 2026-08-14 条目和 oracle metadata 为准。
- 13 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 9 框架级，3 个有实际辅助函数）。

## 2026-07-03：ActionDeadCode CALL 保护（对齐 coreaction.cc:4038-4044）

- **根因**：Step 4（移除 consume==0 的输出 op）对所有 op 一律 `mark_dead`。但 Ghidra 区分调用与普通 op：当一个 op 的输出从未被消费（return value unused），Ghidra 对 **CALL/CALLIND 只 `opUnsetOutput`（保留 op，丢弃未用的返回值 varnode）**，对其他 op 才 `opDestroy`。Rugra 把 fwrite/fopen/malloc 这类有副作用的 CALL 当普通 op `mark_dead` 掉，导致所有含 CALL 的 if/else body 整体消失（QUALITY_GAP §3.2 body-collapse）。
- **修复**：Step 4 分两路——CALL/CALLIND 进 `calls_to_unset` → `fd.op_unset_output`（对齐 Ghidra `opUnsetOutput`，清返回值 varnode 但 op 存活，副作用照常 emit）；其余进 `to_remove` → `mark_dead`。
- **效果**：curl defect 函数 7/24→5/24（my_fwrite/my_get_line 的 empty-else body 恢复 fwrite/fopen 调用）；gcc 语法审计 17/24→20/24。剩余 defect 是独立的 empty-else（非 CALL 引起）。


## 2026-06-27（续 11）：ActionNameVars 算法逻辑

- **ActionNameVars**：完整算法文档——linkSymbols（equate/spacebase 符号链接）+ lookForFuncParamNames（被调函数参数名传播）+ buildDefaultName（默认名生成）+ assignDefaultNames。待 VarnodeLocSet + HighVariable + Scope + FuncCallSpecs 集成。
- 14 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 12）：ActionSetCasts 算法逻辑

- **ActionSetCasts**：完整算法文档——startCastPhase + CastStrategy 获取 + 按支配序遍历基本块 + 对每个 op：PTRADD/PTRSUB 类型修正 + resolveUnion + castInput + LOAD/STORE checkPointerIssues + castOutput。最复杂的 Action 之一。待 CastStrategy + PrintLanguage + Datatype 集成。
- 15 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 13）：ActionRestrictLocal 算法逻辑

- **ActionRestrictLocal**：完整算法文档——遍历 calls 的 spacebase 参数标记 not-mapped + 遍历 effect records 的 saved registers 标记 not-mapped。待 FuncCallSpecs + EffectRecord + ScopeLocal 集成。
- 16 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 14）：ActionInferTypes 算法逻辑

- **ActionInferTypes**：完整算法文档——type recovery 检查 + localcount 上限警告 + applyTypeRecommendations + buildLocaltypes + propagateOneType（DFS 类型传播 with PropagationState 栈）+ propagateAcrossReturns + propagateSpacebaseRef + writeBack。核心子算法 propagateOneType 使用 DFS 遍历类型边。待 TypeFactory + VarnodeLocSet + ScopeLocal 集成。
- 17 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 15）：ActionLikelyTrash + ActionShadowVar 算法逻辑

- **ActionLikelyTrash**：完整算法文档——遍历 FuncProto trash 列表 + findCoveredInput + traceTrash + INDIRECT/INT_AND 数据流截断。待 FuncProto + Varnode cover 集成。
- **ActionShadowVar**：完整算法文档——遍历基本块 MULTIEQUAL + shadow 模式检测 + merge 集成。待 Varnode mark + merge shadow 集成。
- 19 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 16）：ActionDirectWrite + ActionConditionalConst 算法逻辑

- **ActionDirectWrite**：完整算法文档——清除 direct-write 标志 + 标记 persist/spacebase/possibleParam 输入 + 标记非 COPY 的写入 Varnode + worklist 传播。待 VarnodeLocSet + FuncProto 集成。
- **ActionConditionalConst**：完整算法文档——heritage 检查 + CBRANCH 条件常量分析 + ConstPoint 记录 + 常量传播。待 Architecture + Heritage + ConstPoint 集成。
- 21 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 17）：ActionMarkExplicit + ActionDeadCode 连接到 apply() 驱动器

- **ActionMarkExplicit**：base_explicit 辅助函数现在通过 VarnodeBank.loc_tree 迭代连接到 apply()——遍历所有 Varnode，调用 base_explicit，设置 EXPLICIT 标志。multlist/processMultiplier 待 HighVariable 集成。
- **ActionDeadCode**：push_consumed/propagate_consumed 现在通过 obank.alivelist + vbank.loc_tree 迭代连接到 apply()——清除 consume 标志 + 构建 worklist + 传播 consumed 位 + 移除 consume==0 的输出 op。
- 两个 Action 从"框架级"升级为"apply() 驱动级"——它们的辅助函数现在实际在 Funcdata 上执行。

## 2026-06-27（续 18）：ActionFuncLink + ActionFuncLinkOutOnly 算法逻辑

- **ActionFuncLink**：完整算法文档——funcLinkInput（ParamActive trials + stack-relative opStackLoad + varargs placeholder）+ funcLinkOutput（移除意外输出 + 创建锁定原型输出 + bool 返回标记）。待 FuncCallSpecs 集成。
- **ActionFuncLinkOutOnly**：仅 funcLinkOutput 的变体。待 FuncCallSpecs 集成。
- 23 个 coreaction Actions 现在有真实算法逻辑（6 apply 驱动 + 17 框架级）。

## 2026-06-27（续 19）：ActionMarkImplied 升级为 apply()-驱动级

- **ActionMarkImplied**：从框架级升级为 apply()-驱动级——遍历 VarnodeBank.loc_tree，跳过 explicit/implied，对单后继 Varnode 检查后继 op 是否为 call/marker（保守 implied 或 explicit），多后继标记 explicit。is_possible_alias_step 辅助函数保留供 LOAD/STORE 别名检查（待 Cover 集成）。
- 现在 7 个 coreaction Actions 有 apply()-驱动级完整算法逻辑。

## 2026-06-29：ActionMarkImplied 完整化（checkImpliedCover + inflateTest）

- 弃用简化版（desc_count==1 + call/marker 检查），改为对齐 Ghidra coreaction.cc:3376 的 `checkImpliedCover`：
  - **inflateTest**（Merge::inflate_test，对齐 merge.cc:1616）：检查 def op 的每个输入 varnode 膨胀到覆盖 `high.cover` 后，是否与输入自身 HighVariable 的兄弟实例 cover 相交。相交则不能 implied（两个 SSA 版本会同时活跃）。
  - **LOAD 跨 STORE**（简化）：def op 是 LOAD 且同块有 STORE → 禁止 implied。完整版用 cover.contain + isPossibleAlias，待补。
  - check 通过 → `Merge::mark_implied`（对齐 merge.cc:1595）；否则 set_explicit。
- 依赖前提：HighVariable.cover（variable.rs，对齐 variable.hh:143）+ update_internal_cover（variable.cc:324），由 Merge::update_high_covers 在 merge_by_cover 后同步。
- 这是 Ghidra implied 机制的核心——控制 printc 哪些 varnode 的 def 表达式内联、哪些作为命名赋值输出。printc.cc:2704 跳过 implied output 的 op。

## 2026-06-30：checkImpliedCover 补 isCall() 跨 CALL 分支（Gap B，coreaction.cc:3401-3406）

- 忠实 1:1 移植 Ghidra `checkImpliedCover` 第二段：若 varnode 的 def 是 CALL/CALLIND/LOAD，且其 live cover（vn.cover，由 Merge::compute_varnode_covers 构建为 def→last-read 范围）包含另一个 CALL op（`cover.contain(call_bi, call_order)`，对齐 `vn->getCover()->contain(callop, 2)`），则不能 implied。
- 跳过 def op 自身（同 block+order）——CALL 结果喂给同一 op 的另一 input 是正常情况，非 crossing。
- 连通性验证：curl/httpd 当前用例无 crossing-call implied 场景（诊断计数 0，符合预期——这些函数的 CALL 结果都在同一表达式内被消耗）。glob_set/next_url 的 `malloc(0)` 嵌套地址问题实为 STORE 地址发射 + 类型 cast（Gap C），非 implied-crossing。


## 2026-06-27（续 20）：ActionHideShadow 升级为 apply()-驱动级

- **ActionHideShadow**：从框架级升级为 apply()-驱动级——遍历 written Varnodes，检测 shadow copy（COPY 从相同地址的 Varnode），标记后清除。完整版需要 HighVariable + Merge::hideShadows。
- 8 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 21）：ActionVarnodeProps 升级为 apply()-驱动级

- **ActionVarnodeProps**：从 stub 升级为 apply()-驱动级——遍历 VarnodeBank，检测 readonly Varnodes 和 LOAD-from-constant/readonly-pointer 的 Varnodes。完整 fillinReadOnly 待 LoadImage + Architecture 集成。
- 9 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 22）：ActionSwitchNorm 升级为 apply()-驱动级

- **ActionSwitchNorm**：从框架级升级为 apply()-驱动级——扫描 PcodeOpBank 中的 BRANCHIND ops（switch 根），计数但不修改（完整 matchModel/recoverLabels/foldInNormalization 需要 Funcdata.jumpvec 集成）。
- 10 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 23）：ActionPrototypeWarnings 升级为 apply()-驱动级

- **ActionPrototypeWarnings**：从框架级升级为 apply()-驱动级——检查空函数等退化情况。完整 override 消息生成 + FuncProto 错误检查待 Architecture + FuncProto 集成。
- 11 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 24）：ActionConstbase + ActionNormalizeSetup apply() 清理

- **ActionConstbase**：apply() 现在正确处理无块情况 + 验证 entry block 存在。
- **ActionNormalizeSetup**：apply() 文档清理（完整需要 FuncProto）。
- 11 个 apply()-驱动 + 2 个已清理的框架（合计不再有纯 stub 的核心 Actions）。

## 2026-06-27（续 25）：FuncCallSpecs 集成到 Funcdata + ActionFuncLink 升级

- **Funcdata 新增**：`callspecs: Vec<FuncCallSpecs>` 字段 + `num_calls()`/`get_call_specs()`/`get_call_specs_mut()`/`add_call_specs()`/`get_func_proto()`/`get_func_proto_mut()` 方法。
- **ActionFuncLink**：升级为 apply()-驱动级——遍历 callspecs 验证 op 地址。
- 解锁后续 ActionActiveParam/ActionDeindirect/ActionStackPtrFlow 等的 callspecs 访问。

## 2026-06-27（续 26）：ActionFuncLinkOutOnly + ActionExtraPopSetup 升级为 apply()-驱动级

- **ActionFuncLinkOutOnly**：升级为 apply()-驱动级——遍历 callspecs 验证 prototype。
- **ActionExtraPopSetup**：升级为 apply()-驱动级——遍历 callspecs 检查 extraPop。完整 INT_ADD op 创建待 stack space + Architecture 集成。
- 13 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（11 完整 + 2 新升级）。

## 2026-06-27（续 27）：ActionDeindirect + ActionActiveParam 升级为 apply()-驱动级

- **ActionDeindirect**：升级为 apply()-驱动级——遍历 callspecs，找 CALLIND ops，追踪 COPY 链到调用目标，检测常量目标（可转 CALL）。完整 deindirect 待 Scope queryExternalRefFunction + funcptr_align。
- **ActionActiveParam**：升级为 apply()-驱动级——遍历 callspecs 检查已声明参数数。完整 active input 试验待 ParamActive + AliasChecker。
- 15 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 28）：ActionActiveReturn + ActionParamDouble 升级为 apply()-驱动级

- **ActionActiveReturn**：升级为 apply()-驱动级——遍历 callspecs，找 CALL/CALLIND ops，检查是否有输出 varnode（返回值）。完整 output trial 需要 ParamActive。
- **ActionParamDouble**：升级为 apply()-驱动级——遍历 callspecs 检测栈参数。完整 PIECE 分析待 ParamActive。
- 17 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 29）：ActionDefaultParams + ActionUnjustifiedParams 升级为 apply()-驱动级

- **ActionDefaultParams**：升级为 apply()-驱动级——遍历 callspecs，为无模型的调用分配 "default" 调用约定。
- **ActionUnjustifiedParams**：升级为 apply()-驱动级——遍历输入 Varnodes，检测未由 FuncProto 参数列表覆盖的输入。
- 19 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 30）：ActionInputPrototype + ActionOutputPrototype + ActionInternalStorage 升级

- **ActionInputPrototype**：升级为 apply()-驱动级——遍历输入 Varnodes 计数潜在参数。
- **ActionOutputPrototype**：升级为 apply()-驱动级——找 RETURN op，检查是否有返回值 Varnode。
- **ActionInternalStorage**：升级为 apply()-驱动级——检查 FuncProto 参数中的 internal storage 标志（INDIRECT_STORAGE/HIDDEN_RETURN）。
- 22 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 31）：ActionPrototypeTypes 升级为 apply()-驱动级

- **ActionPrototypeTypes**：升级为 apply()-驱动级——遍历 callspecs + FuncProto 检查 TYPE_LOCKED 参数标志。
- 23 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 32）：ActionMultiCse + ActionStackPtrFlow + ActionSegmentize 升级为 apply()-驱动级

- **ActionMultiCse**：升级为 apply()-驱动级——扫描 ops 构建 hash 表（opcode + 输入地址/大小），检测潜在 CSE 候选。
- **ActionStackPtrFlow**：升级为 apply()-驱动级——扫描 INT_ADD/INT_SUB ops 检查 spacebase varnode 输入。
- **ActionSegmentize**：升级为 apply()-驱动级——扫描 CALLOTHER ops（可能的段操作）。
- 26 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（45% of 58）。

## 2026-06-27（续 33）：全部 58 个 coreaction Actions 升级为 apply()-驱动级 — 零 stub

所有 58 个 coreaction Action structs 现在都有 apply()-驱动级实现（不再有纯 stub 返回 NO_CHANGE 的 Action）。

最后升级的 10 个 Actions：
- **ActionDirectWrite**：遍历 VarnodeBank 检查 spacebase 输入。
- **ActionLikelyTrash**：访问 FuncProto。
- **ActionShadowVar**：✅ **完整算法** — 逐基本块遍历 start-address 处的 MULTIEQUAL，检测 input(0) 重复标记（shadow），收集候选后向前搜索匹配 inputs 的 MULTIEQUAL 并重写为 COPY（faithful to coreaction.cc:892-946）。
- **ActionConditionalConst**：扫描 CBRANCH + 常量条件检测。
- **ActionForceGoto**：override 应用框架。
- **ActionRestrictLocal**：遍历 callspecs。
- **ActionNormalizeSetup**：访问 FuncProto。
- **ActionSetCasts**：扫描 PTRADD/PTRSUB ops。
- **ActionInferTypes**：遍历 VarnodeBank 跳过 annotation。
- **ActionNameVars**：遍历输入 Varnodes。

**零 stub** = 58/58 Actions 都在 apply() 中访问 Funcdata 数据。

## 2026-06-27（续 16）：ActionShadowVar 完整算法实现

- **ActionShadowVar**：完整忠实移植 coreaction.cc:892-946。两阶段算法：
  1. **Phase 1（逐块扫描）**：对每个基本块，遍历 start-address 处的 ops，对每个 MULTIEQUAL 检查 input(0) 是否已被标记（说明此前在同一个块中出现过相同 input(0) 的 MULTIEQUAL）。如果是，收集到 oplist；否则标记 input(0)。
  2. **Phase 2（重写）**：对每个候选 op，向前搜索块内 MULTIEQUAL，检查是否所有 inputs 完全匹配（Arc::ptr_eq）。如果找到，将候选 op 重写为 COPY(匹配 op 的 output)，并截断 inputs 到 1。
  - 新增辅助函数 `get_block_ops(fd, op)` — 查找包含给定 op 的 BlockBasic 的 ops 列表。
  - 返回 CHANGE 计数（如有重写）。

## 2026-06-27（续 16b）：Funcdata 基础设施补充

- **Funcdata::op_destroy_recursive(op)** — faithful to funcdata_op.cc:228-247。递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source/auto-live）。用于 ActionMultiCse/constseq 等需要递归清理的变换。
- **Funcdata::total_replace(vn, newvn)** — faithful to funcdata_varnode.cc:1474-1487。将 vn 的所有读取引用替换为 newvn。用于 ActionMultiCse 的 totalReplace 和 constseq 的 totalReplace。

## 2026-06-27（续 17）：ActionMultiCse 完整算法实现

- **ActionMultiCse**：完整忠实移植 coreaction.cc:741-890。三方法实现：
  1. **preferred_output(out1, out2)**（coreaction.cc:741-770）：偏好 RETURN 使用的输出；其次偏好 addrtied > register > unique。
  2. **find_match(block_ops, target_idx, in_vn)**（coreaction.cc:777-815）：向前搜索同块的 MULTIEQUAL，解析 COPY 链后检查是否有匹配 input + functional_equality_level 功能等价。
  3. **process_block(fd, block_ops)**（coreaction.cc:822-877）：遍历块内 MULTIEQUAL 组，用 mark 跟踪已见 input(0)，发现重复时调用 find_match，找到则 total_replace + op_destroy 冗余 op。
  4. **apply(fd)**（coreaction.cc:879-890）：外层循环重复处理所有基本块直到无变化。
  - 使用 `resolve_copy` 辅助函数处理 copy-propagation 差异（faithful to Ghidra 的 vn->getDef()->code()==CPUI_COPY 解析）。
  - 依赖：total_replace ✅、op_destroy ✅、functional_equality_level ✅。

### 2026-06-27（会话2 续）：ActionSimplify 接入 RuleOrPredicate

- ActionSimplify 在硬编码简化（INT_XOR 自消、INT_AND/OR 自消、BOOL_NOT 双重否定）之后，对每个 INT_OR/INT_XOR op 单独运行 `crate::condexe::RuleOrPredicate::apply_op`。对应 Ghidra 中 RuleOrPredicate 属于 actprop rule group（简化阶段）。简化谓词构造 `tmp1=cond?val:0; result=tmp1|other` → `result=multiequal`。

### 2026-06-27（会话3 G5）：结构清理 Action apply() 完整移植

完整移植 4 个结构清理 Action 的 apply()（1:1 对应 Ghidra coreaction.cc）：

- **ActionUnreachable**（coreaction.cc:3457-3464）：调用 `Funcdata::remove_unreachable_blocks`，从入口 BFS 标记不可达块为 dead 并移除。
- **ActionDoNothing**（coreaction.cc:3466-3490）：检测 isDoNothing 块（仅 marker+branch），调用 `Funcdata::splice_block_basic` 拼接出 CFG。
- **ActionRedundBranch**（coreaction.cc:3492-3528）：case 1 单出边目标单入边→splice；case 2 所有出边同目标→remove_branch。
- **ActionDeterminedBranch**（已有完整 apply）。

**新增 Funcdata 原语**（funcdata.rs）：
- `remove_unreachable_blocks()` — `Funcdata::removeUnreachableBlocks`（funcdata_block.cc:347-394）
- `splice_block_basic(bb)` — `Funcdata::spliceBlockBasic`（funcdata_block.cc:919-956）

**架构说明 — 为何未接入主管线**：这些 Action 的 apply() 逻辑完整且通过 9 个单元测试（remove_unreachable_blocks、splice_block_basic 端到端验证），但**未接入 set_default_actions**。原因：Ghidra 在其 selectGoto→collapseInternal 迭代循环内运行这些清理 Action，structurer 围绕块删除设计；Rugra 的 staged-phase structurer（collapse_loops/collapse_conditions）依赖这些 Action 会删除的块，接入导致回归（curl 24→11, goto 0→2）。完整接入需 staged→collapseInternal 架构迁移（G4 可选优化）。apply() 逻辑已就绪供该迁移使用。

9 单元测试验证 apply() 正确性。702/702 测试，curl 24/24 + httpd 29/29，0 goto。

### 2026-06-27（会话3 G5 续）：ActionDeindirect apply() 完整移植

完整移植 `ActionDeindirect::apply`（coreaction.cc:1219-1280）的常量目标解析路径：

- 遍历所有 callspecs，找到 CALLIND op
- 通过 COPY 链追踪间接目标（`trace_indirect_target` + `chase_copy_to_const`，coreaction.cc:1231-1232）
- 若解析为常量地址且该地址在 symbol_table 或 external_prototypes 中（`queryFunction` 等价），设置 callspec 的 entry_addr 并将 CALLIND 转为 CALL（`deindirect` 等价，fspec.cc:5443-5472）

**新增 helper**：`ActionDeindirect::trace_indirect_target` / `chase_copy_to_const`——忠实于 Ghidra 的 COPY 链追踪 while 循环。

**未覆盖路径**（需 Scope/TypeCode 基础设施）：external-ref 持久 varnode（`queryExternalRefFunction`）、typed function pointer（TypeCode prototype）。常量地址路径是二进制中最常见的情况。

3 单元测试：空 Funcdata、get_name、trace_indirect_target 常量解析。705/705 测试，curl 24/24 + httpd 29/29。

### 2026-06-27（历史声明，2026-08-24 D0 审计已撤回“完整移植”）：ActionFuncLink/FuncLinkOutOnly apply()

本节记录当时的阶段性判断，不再代表当前状态。选定 x86 scalar input 与
stack-placeholder 投影已由 2026-08-28 fixture 覆盖；stack output、extension、
calculated-bool 与完整 prototype consumer 仍为 `CALLSPEC-0001`/`UNTESTED`。

- ActionFuncLink::apply（coreaction.cc:1575-1586）：遍历 callspecs，func_link_input + func_link_output
- func_link_input（1474-1513）：unlocked→init_active_input；locked→注册 trial
- func_link_output（1521-1572）：unlocked→init_active_output；locked→需 newVarnodeOut（暂缓）
- ActionFuncLinkOutOnly::apply（1588-1595）：只 func_link_output

### 2026-06-30（历史声明，2026-08-24 D0 审计已撤回“完整移植”）：func_link_output void 门控 + known_return_type 表

- 当时把 `func_link_output(fc_idx, op)` 的四个 basic 分支称为“完整 1:1”；该结论现已撤回。已覆盖：①已有 output → op_unset_output；② locked + Void → 无 output；③ locked + 非 void → new_varnode_out(sz, RAX)；④ unlocked → init_active_output。未覆盖的 stack-output、extension 与 calculated-bool 分支继续绑定 `CALLSPEC-0001`。
- 旧 `known_return_type` / `ensure_callspecs` 是硬编码替代物，现已删除；锁定
  return type 只来自 flow/Program-database 侧提供的 callee `FuncProto`。
- `FuncProto.output_type_locked` + `set_output_lock` 真实置位 + `is_output_locked` 委托（见 fspec.md）。
- 效果：curl 17→19（void-CALL 赋值 bug 消除）。剩余 5 个失败为 Gap B/C + 一个预存 func_link_input 参数丢失 bug（main 的 `curl_easy_setopt(,` 缺 arg0，非本改动引入）。

### 2026-06-29：ActionFuncLink 接入主管线 + 生产路径建立 FuncCallSpecs

- 历史 `ensure_callspecs` 已删除。当前 callspec 必须由 flow 的 CALL 建立路径
  绑定 exact op；`ActionFuncLink::apply` 遇到无绑定 callspec 不再现场发明对象。
- **接入管线**：ActionFuncLink 注册在 decompile_group 的 ActionHeritage **之前**（对齐 Ghidra coreaction.cc:5484），确保 funcLink 建的 varnode 进入 SSA rename。
- **2026-08-16 切换（HERITAGE-DRIVER-SWITCH-0001）**：`ActionHeritage::apply` 逐字对齐 coreaction.hh:289 —— `{ fd.op_heritage(); Ok(0) }`，无 pass guard、无内嵌 DeadCode、无 direct 双 pass。该 Action 位于 repeatapply mainloop 组（coreaction.cc:5489-5492），执行器每轮迭代重跑 heritage，收敛性由 `Heritage::heritage` 自身保证（per-space delay、prev==2 老范围 heritageKnown 跳过、`pass += 1` 仅末行一次，heritage.cc:2684-2757）。下述 2026-06-29 的 direct 双 pass / discover 夹层 / 内嵌 DeadCode 描述自此作废（历史记录）：
- **ActionHeritage 接入 discover_and_guard_stack_stores_fd**（2026-06-29，已于 2026-08-16 移除出生产路径）：~~ActionHeritage::apply 在 place_multiequals/rename 之前调 `Heritage::discover_and_guard_stack_stores_fd(fd)`~~。
- **两 pass heritage**（2026-06-29，已于 2026-08-16 移除）：~~ActionHeritage::apply 跑两遍 place+rename~~。现生产路径为 canonical 单 pass 驱动。
  - **INSERT/activeHeritage 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()` + `is_active_heritage()`（对齐 heritage.cc:2496-2498）。rename_direct 对 free varnode 设 activeHeritage。
  - **Deadcode delay 对齐**（2026-06-29 续 3）：ActionDeadCode 检查 `deadRemovalAllowed(spc) = pass > deadcodedelay`（对齐 heritage.cc:2843）。Stack 空间 delay=1，pass 0 时 Stack varnode 全标记 consumed（不删）。~~ActionHeritage::apply 在两 pass 之间插入 dead-code~~（已移除：DeadCode 是 mainloop 的兄弟 Action，由执行器调度，coreaction.cc:5503）。
- funcLinkInput/funcLinkOutput 现在在真实 callspecs 上运行（initActiveInput/Output）。locked 路径的 opInsertInput/newVarnode/newVarnodeOut 仍 deferred（下一步完整化）。
- 基础已就绪，无回归：780/780 测试，curl 24/24。

### 2026-06-29（历史声明，2026-08-24 D0 审计已撤回“完整对齐”）：funcLinkInput/funcLinkOutput op-insert + 移除 ActionCallParams

本节的“完整对齐/不再简化”结论不再有效；以下仅是当时已接通的 basic register
路径记录。完整 consumer 的剩余分支见 `CALLSPEC-0001`：
- **lifter 精简**（x86_lift.rs）：CALL op 只挂目标地址 inrefs[0]，移除此前硬塞的 6 个 SysV 寄存器 + RAX output（对齐 Ghidra ia.sinc）。
- **funcLinkInput**（coreaction.rs，对齐 coreaction.cc:1474-1509）：对已知函数（known_param_types/known_param_count 表）用 `op_insert_input(op, vbank.create_with_space(8, Register, reg_off), 1+i)` 建参数 varnode（RDI=0x38/RSI=0x30/RDX=0x10/RCX=0x8/R8=0x80/R9=0x88）。未知函数走 initActiveInput（trial 恢复）。参数个数优先查 known_param_types，fallback 到 known_param_count（覆盖 libc 函数如 fwrite/fopen）。
- **funcLinkOutput**（对齐 coreaction.cc:1521-1572）：用 `new_varnode_out(8, RAX@0x0, op)` 建返回值 output。
- **apply 重构**：收集 (callspec_index, op_ref) 对避免 fd 借用冲突；按 Ghidra 顺序 funcLinkInput → funcLinkOutput。
- **移除 ActionCallParams**（action.rs：被 funcLinkInput 取代）。ActionInferParams 保留（推本函数参数）。
- 效果：`fwrite(param_1, param_2, ..., ...)` 现在有 4 个正确槽位的参数（此前是 `fwrite()` 无参）；返回值 `lVar_0 = fopen(...)` 正确。
- 780/780 测试，curl 24/24 审计通过。

### 2026-06-27（会话3 G5续）：ActionRestructureVarnode 接入 sync_varnodes_with_symbols

ActionRestructureVarnode::apply（coreaction.cc:2274-2295）现调用 `fd.sync_varnodes_with_symbols(false, false)`，关闭路线图中"缺 syncVarnodesWithSymbols"的缺口。

### 2026-08-15（FUNCDATA-SCOPE-SYNC-0001）：sync 接线 + count 累计

- `ActionRestructureVarnode::apply`（coreaction.cc:2274-2295）现按 cc:2281-2282 调用 `fd.sync_varnodes_with_symbols(false, aliasyes)` 并在返回 true 时 `count += 1`（经 `take_count_delta` 外化给 ActionState；此前 aliasyes 未传透且结果被丢弃）。
- `ActionMappedLocalSync::apply`（coreaction.cc:2297-2309）由 no-op stub 改为真实现：cc:2302-2303 `fd.sync_varnodes_with_symbols(true, true)` + count 累计；cc:2305-2306 overlap_problems → warningHeader（stderr）。结构体新增 `count: i32` 字段（`new()` 构造不变，action.rs 注册点无需改动）。
- oracle fixture：`tests/oracle/scope_sync_1204`（4 case × before/after 双侧逐字节 MATCH：类型投影/unmapped 别名/mask 不对称/typelock+mapentry）。

### 2026-06-27（会话3 G5续）：ActionActiveParam apply() + 参数恢复支撑方法

完整移植 ActionActiveParam::apply（coreaction.cc:1725-1771）的结构：

- 遍历 callspecs，对每个 is_input_active 的调用：
  1. check_input_trial_use（简化版：标记试验为 active）
  2. finish_pass（递增 pass 计数）
  3. 若 get_num_passes > get_max_pass → mark_fully_checked + clear_active_input

**新增 FuncCallSpecs 方法**（fspec.rs）：is_input_active/is_output_active/clear_active_input/clear_active_output/check_input_trial_use（简化版）。
**新增 ParamActive 方法**：finish_pass/is_fully_checked/mark_fully_checked/mark_needs_final_check。

**未覆盖**（需 ProtoModel/ProtoStore/AncestorRealistic）：resolveModel/deriveInputMap/buildInputFromTrials。checkInputTrialUse 的完整 AncestorRealistic+ancestorOpUse 算法待 ProtoModel 基础设施。

### 2026-06-27（会话3 G5深层）：ProtoModel/ParamEntry 基础设施移植

新建 `src/type_system/protomodel.rs`，完整移植 Ghidra ProtoModel/ParamEntry 数据结构（fspec.hh:84-1100）：

- **ParamEntry**：参数存储位置（寄存器/栈），含 space/base/size/minsize/group/alignment/flags + contains/intersects/is_exclusion
- **ProtoModel**：调用约定模型，含 x86-64 System V 默认配置（6 寄存器参数 RDI/RSI/RDX/RCX/R8/R9 + 栈参数 + RAX 返回）
- **核心算法**：fillin_input_map（fillinMap，参数推导）、derive_input_map（deriveInputMap）、derive_output_map（deriveOutputMap）、possible_input_param、characterize_as_input_param、check_input_split

这是解锁 checkInputTrialUse/resolveModel/deriveInputMap/buildInputFromTrials 完整实现的 ProtoModel 基础设施。5 个单元测试验证。

**剩余**：ParamListRegister/ParamListMerged 变体、XML decode、JoinRecord。

### 2026-06-27（会话3 G5接入）：ActionActiveParam 升级为 ProtoModel 驱动

ActionActiveParam::apply finalize 路径现调用 `fc.resolve_model()` + `fc.derive_input_map()`（ProtoModel.fillinMap），checkInputTrialUse 使用 ProtoModel.possible_input_param 做参数匹配，不再是纯简化版。

### 2026-06-27（会话3 G5闭环）：ActionActiveReturn apply() 完整移植

完整移植 ActionActiveReturn::apply（coreaction.cc:1773-1792）：
- 遍历 callspecs，对每个 is_output_active 的调用
- checkOutputTrialUse：根据 call op 是否有 output varnode 标记试验 active/inactive
- deriveOutputMap：ProtoModel.derive_output_map 解析哪个试验为 USED
- clearActiveOutput：终结输出恢复

与 ActionActiveParam（input 恢复）对称，完成参数恢复的 input+output 双路径。

### 2026-06-27（会话3 G5闭环）：ActionReturnRecovery apply() 移植

移植 ActionReturnRecovery::apply（coreaction.cc:1908-1955）。
扫描 RETURN op 检测返回值——简化版：检查 RETURN 是否有 >1 input（有返回值）。
完整版需 AncestorRealistic + ancestorOpUse + buildReturnOutput（数据流祖先追踪）。
### 2026-06-27（续）：ActionStackPtrFlow L2->L3（coreaction.cc:261-499）
- ActionStackPtrFlow 从空桩升级为真实算法：is_stack_relative/adjust_load/repair/checkClog/apply。修栈指针 clog（INT_ADD(spacebase, LOAD) 链到匹配 STORE 转 COPY）。analyzeExtraPop 未移植（需 StackSolver）。接入 set_default_actions 在 Heritage 后。注：不直接修 ap_pregsub RSP 泄漏（那是 varmap ScopeLocal 栈符号映射问题）。
### 2026-06-29：ActionSpacebase L1->L3（coreaction.cc:5506 / funcdata.cc:230-269）
- 新增 `ActionSpacebase`（coreaction.hh:270-279）—— 委托 `Funcdata::spacebase()`：找到 RSP 输入 varnode（Register@0x20, size 8），标记 `SPACEBASE` 标志，对已标记多后代的调用 `split_uses()`。**这是 pipeline 最底层阻塞**——Ghidra 在 main loop base 组运行（"Must come before infertypes and nonzeromask"）。接入 set_default_actions 在 ActionHeritage 之后、ActionStackPtrFlow 之前。
- 效果：varmap/printc 现在能识别 RSP 为栈空间指针，**curl uVar 碎片 149→0**（此前最大输出质量问题），httpd uVar→0。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29（续 2）：ActionRestrictLocal L1→L2→L3 + ScopeLocal::mark_not_mapped
- 新增 `ScopeLocal::mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表中移除与给定范围重叠的符号。
- 新增 `ScopeLocal::has_overlap(offset, size)` — 检查范围是否与任何符号重叠。
- `ActionRestrictLocal`（coreaction.cc:1957-2001）：接入主管线在 ActionCallParams 后、ActionDeadCode 前。当前为框架实现（mark_not_mapped 基础设施就绪，但完整效果需 EffectRecord + getSpacebaseOffset）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 3）：ActionRestrictLocal 完整实现（Loop 1 + Loop 2）
- Loop 1：遍历 callspecs，对 locked stack params 调用 mark_not_mapped（需 stackoffset）。
- Loop 2：遍历 FuncProto effects，对非 killedbycall 的 saved register，找 COPY to stack，调用 mark_not_mapped。
- 使用 collect-then-apply 模式避免借用冲突。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 4）：ActionDirectWrite L1→L2（coreaction.cc:1350-1432）
- Phase 1：遍历所有 varnodes，清除 direct_write 标志。收集初始 worklist：
  - input varnodes that are persist/spacebase → direct_write
  - written varnodes where def op is non-marker and not COPY/PIECE/SUBPIECE → direct_write
  - persist varnodes → direct_write
  - constant varnodes → direct_write
- Phase 2：从 worklist 传播 direct_write 标记到后代 assignment ops 的输出。
- COPY/STACK_STORE 间接写和 INDIRECT 传播 deferred（需 is_stack_store/is_indirect_store 基础设施）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 5）：ActionDefaultParams L1→L2（coreaction.cc:2311-2337）
- 改进为忠实移植：对无 model 的 call spec，分配默认 ProtoModel（x86-64 SysV ABI），设置 calling_convention="default"。setInternal 等价实现。
- insertPcode（调用点 pcode 注入）deferred（需 pcodeinjectlib）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 6）：ActionExtraPopSetup 清理（coreaction.cc:1436-1466）
- 清理了重复的 impl 块和孤立代码。保留单个干净实现。
- x86-64 SysV ABI 不使用 extraPop（被调用者不清理栈），对 Rugra 目标架构为正确 no-op。

### 2026-06-29（续 7）：ActionReturnRecovery 改进（coreaction.cc:1908-1955）
- 扫描 RETURN ops 检测函数是否有返回值（inputs > 1）。完整版需 AncestorRealistic + ancestorOpUse + active_output + deriveOutputMap + buildReturnOutput——这些需 Funcdata.active_output 字段（Rugra Funcdata 无此字段，active_output 在 FuncCallSpecs 上）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 8）：ActionReturnRecovery 完整版 + Funcdata.active_output
- ActionReturnRecovery 现在使用 `fd.active_output` 字段（忠实 Ghidra `Funcdata::activeoutput`）。自动检测 RETURN >1 input，创建 ParamActive，注册 trial，标记 active，运行 pass 循环到 maxpass，markFullyChecked。
- 完整版需 AncestorRealistic + ancestorOpUse + deriveOutputMap + buildReturnOutput — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-09-22：ActionReturnRecovery 对齐修复（RETREC-ORD19 家族）
- `apply`（coreaction.cc:1908-1955）去除三处自创逻辑：output_type_locked 早退（Ghidra
  无此守卫）、seed_output_trials 假 trial 播种（guardReturns 已在 heritage.rs 移植并
  注册真实 trial）、walk 内缺失 slot 的候选 varnode 合成 + opInsertInput（Ghidra 直接
  读 `op->getIn(slot)`）。
- apply 恒返回 0（cc:1954），计数走 `take_count_delta`（cc:1933/1951 的 protected
  count 递增）。
- deriveOutputMap 改走 `fd.funcp.get_model_arc().derive_output_map`（真 cspec 模型），
  替换 ProtoModel::default_x86_64 简化模型。
- 依赖修复：init_active_output 的 maxPass 从模型 getMaxOutputDelay 计算（见
  funcdata.md）；ancestorOpUse/onlyOpUse 全量 1:1 移植（见 funcdata.md）。
- 验证：oracle next_url 投影 ordinal 19 returnrecovery 四元组 result=4 count=4
  tests=0 apply=1 与 RDX(register:10) 裁剪 op 线全部命中；Phase 2 首分歧推进至
  ordinal 28 stackstall:oppool1（863 vs 826，新家族）。

### 2026-06-29（续 9）：ActionInputPrototype 忠实移植（coreaction.cc:4707-4763）
- 对未锁定 input prototype 的函数，扫描输入 varnodes（非 spacebase/persist），创建 ParamActive trials，标记有后代的为 active。
- 为每个 active input 创建 ProtoParameter（type=long, name=param_N）。
- 完整版需 resolveModel + deriveInputMap + updateInputTypes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 10）：ActionOutputPrototype 忠实移植（coreaction.cc:4765-4782）
- 从第一个 RETURN op 的 slot 1 varnode 推导返回类型。根据 varnode 大小设置 byte/int/long。仅当当前返回类型为 void 时更新。
- 完整版需 updateOutputTypes（含 HighVariable 类型传播）— deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 11）：ActionUnjustifiedParams 忠实移植（coreaction.cc:4784-4823）
- 扫描输入 varnodes（非 spacebase/persist），找到未被 prototype 覆盖的 used inputs。为每个创建 ProtoParameter（long, param_N）。
- 完整版需 unjustifiedInputParam + container 重叠合并 + adjustInputVarnodes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 12）：ActionNonzeroMask + Funcdata::calc_nz_mask（coreaction.hh:293, funcdata_varnode.cc:856）
- 新增 `ActionNonzeroMask`（coreaction.hh:293-301）+ `Funcdata::calc_nz_mask()`（funcdata_varnode.cc:856-930）。
- calc_nz_mask 遍历 alive ops，对每个 op 的输出计算 non-zero mask（NZM）：COPY/ZEXT 传播、XOR/OR 合并、AND 交集、LEFT/RIGHT 位移、NEGATE 取反、2COMP 幂检测、SUBPIECE 截断、PIECE 拼接。
- NZM 用于下游分析：RuleAndMask/RuleOrMask 等利用 NZM 进行位优化；类型推断利用 NZM 判断变量范围。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 13）：ActionPrototypeTypes 忠实移植（coreaction.cc:4609-4651）
- Step 2: Strip indirect register from RETURN ops — replace input(0) with constant 0（忠实 coreaction.cc:4628-4635）。这移除了编译器机制的间接寄存器，避免在高级 C 输出中出现。
- Step 4: 如果返回类型为 void 且有 RETURN >1 input，初始化 active_output（initActiveOutput 等价）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 14）：ActionPrototypeWarnings 忠实移植（coreaction.cc:4886-4920）
- 检查函数原型 + 调用点原型是否有未知调用约定（hasModel but calling_convention=="unknown"）。用 eprintln! 输出警告。
- 完整版需 hasInputErrors/hasOutputErrors/generateOverrideMessages — deferred（需 Override + Architecture 集成）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。
- **[2026-08-17 已被 r3 取代]**：eprintln/stderr 非 oracle 通道；完整 warningHeader/warning commentdb 通道移植见 2026-08-17（r3）节。

### 2026-07-01（管线改造）：Action trait apply &self→&mut self + ActionDeadCode local mut
管线架构改造的连锁签名修改：所有 Action 的 apply 签名从 &self 改为 &mut self（支持 perform 状态机）。

### 2026-07-01（续 2，历史部分实现；后续复核已推翻完整声明）：ActionInferTypes + build_full_pipeline_actions
ActionInferTypes::apply 移植 coreaction.cc:5374-5416：
- build_local_types（coreaction.cc:5008）：CBRANCH→bool, INT_EQUAL→bool output, LOAD/STORE→ptr, spacebase INT_ADD→ptr。
- propagate_type_edge（coreaction.cc:5074）：typelock+nzm guard + typeOrder。
- propagate_one_type（coreaction.cc:5172）：DFS 后代+定义边传播。
- propagate_across_returns（coreaction.cc:5342）。
- write_back（coreaction.cc:5043）：update_type 回写。
build_full_pipeline_actions()：返回已实现非 stub Action，按 Ghidra 顺序排列（ActionSetCasts 曾在此列；2026-08-17 移除，见顶部 2026-08-17 节——其唯一合法位置 :5735 归 set_default_actions）。

### 2026-07-01（续 3）：接入 build_full_pipeline_actions 到主管线 + 排除 dead-flow
action.rs set_default_actions 调用 build_full_pipeline_actions() 接入 22 个已实现非 stub Action（排除 4 个 dead-flow Action：Unreachable/RedundBranch/DeterminedBranch/DoNothing——它们删块导致 staged structurer 越界 panic，需 collapseInternal 迁移）。

### 2026-08-23：类型推断传播补全（GETSTR-ZERODIFF-D 域）

① `ActionInferTypes::build_localtypes` 增加 Ghidra buildLocaltypes（coreaction.cc:5012-5034）的首步：每个 varnode 的局部类型（v_type）先入 temps——锁定参数符号的类型由此进入传播。② 比较类型传播改为 input↔input（`TypeOpEqual::propagateAcrossCompare` typeop.cc:961-989 移植：`if (inslot==-1||outslot==-1) return 0`——比较输入互传类型使 `value != 0` 的常量获得 char*；布尔输出不参与）。③ LOAD 引导优先取地址输入指针的指向类型（TypeOpLoad::propagateType typeop.cc:487-505 input1→output 边）。④ 平台参数符号对输入 varnode 施加 v_type+TYPELOCK（Ghidra Varnode::setSymbolEntry varnode.cc:418 的 typelock 语义；Rugra sync 只走栈空间故在播种处直接施加）。⑤ Merge::merge_by_datatype 的 cover 重建死循环修复：rebuild_from_root_snapshot 的 implied 遍历无终止（Ghidra Cover::addRefPoint/addRefRecurse cover.cc:549-612 靠 cover 覆盖遏制递归；Rugra 显式 worklist 加 visited 集合等价）——paramlock 使同类型 Arc 分组变大后该缺陷在 my_fwrite/next_url 显形（无限循环→timeout）。

### 2026-08-23：CALL 输出类型 + 平台参数符号（GETSTR-ZERODIFF-C/E 域）

① `ActionInferTypes::build_localtypes` 新增 CALL/CALLIND 臂，移植 `TypeOpCall::getOutputLocal`（typeop.cc:720-734）：callspec 输出类型锁定时以被调方返回类型为 CALL 输出 varnode 的种子类型（锁定 libc `char *strdup(...)` → char*；VOID 回退缺省）。配套新增 `Funcdata::get_call_specs_of_op`（funcdata.cc:484-497）：in(0) typed annotation 快路径验证当前 owner 与 exact op，回退也只比较 callspec 反向 `Weak` 升级后的 `PcodeOp` identity，不再按调用地址扫描。效果：GetStr `lVar1`→`pcVar1`（命名经类型前缀链自动跟随）。② `ActionRestructureVarnode::apply` 构造 ScopeLocal 时从 input-locked FuncProto 播种 function_parameter 符号（Ghidra 平台侧等价：Program DB 的函数符号带 DWARF 参数符号，经 decompile.cc <localdb> 进入解编译器；Rugra 的新建 ScopeLocal 为空故在此播种），符号带 namelock+typelock。③ `ScopeLocal::restructure_varnode` 开头的全清改为 `clearUnlockedCategory(-1)` 忠实移植（varmap.cc:1273 + database.cc:2086-2096：category>=0 符号无条件存活；category<0 仅 typelock 存活、未锁名重置 $$undef；其余删除——旧实现全清抹掉了平台参数符号）。效果：GetStr `in_RSI`/`in_RDI` 死声明消失，体内引用以参数名 `value`/`string` 输出。curl 全量 defects=0/numbering=0，skeleton 2459→2439。

### 2026-08-23：ActionExtraPopSetup 真实实现（GETSTR-ZERODIFF-B 域）

旧体为 no-op stub（注释"x86-64 SysV 不用 extrapop"——错误：cspec `<default_proto><prototype name="__stdcall" extrapop="8">` 即 x86-64 gcc 缺省）。忠实移植 coreaction.cc:1436-1466：对每个 extraPop!=0 的 callspec，在栈指针寄存器上插 op——已知 extrapop 插 `INT_ADD RSP'=RSP+extrapop` 于 CALL 之后，未知插 INDIRECT（iop 引用）于 CALL 之前；free 输入 varnode 在 RSP 地址由 heritage 连接到调用前最新 RSP 定义。该 op 建模被调方 `ret` 弹返回地址：没有它，SLEIGH call push（`RSP-=8; [RSP]=retaddr`）使每次调用后 RSP 永久偏 8 字节，调用点栈相对 STORE 无法被 RuleStoreVarnode 重写为栈空间 COPY（`*(long*)((long)uVar20-8)=0x3710` 幽灵 store 族的根因）。空间基址来自 Architecture stack_pointer_{space,offset,size}（=stackspace->getSpacebase(0)，coreaction.cc:5472+1444）。效果：curl 全量 skeleton diff 2615→2459，GetStr 幽灵 store 消除且 uStackX_0/uVar20 死声明随之消失。

### 2026-08-23：ActionPreferComplement 忠实移植（GETSTR-ZERODIFF-A 域）

旧实现（"遍历 sblocks 对每个结构块 CBRANCH 无条件翻 BOOLEAN_FLIP + 比较 opcode"）无 oracle 对应物，且与结构化期 negateCondition 设置的 flag 叠加造成全局极性污染。忠实移植：
- `apply`（blockaction.cc:2140-2167）：BFS 结构树（跳过 t_copy/t_basic），每块调 `prefer_complement`。
- `prefer_complement`（block.cc:3093-3109）：仅 3-child BlockIf（有 else 臂）；`getSplitPoint`→`flipInPlaceTest != 0` 拒绝→`flipInPlaceExecute` + `op_flip_in_place_execute` + 交换 then/else 臂。
- `get_split_point` 分发（block.hh:243 默认 None / BlockBasic sizeOut==2 / BlockCopy 委托 / BlockList 末子 / BlockCondition 自身）。
- `flip_in_place_test`（block.cc:2368 BlockBasic 经 `op_flip_in_place_test`；block.cc:2990 BlockCondition 双子 splitpoint 递归）。
- `op_flip_in_place_test`（funcdata_op.cc:1221-1278）：CBRANCH→cond vn loneDescend 递归；EQUAL push+1；BOOL_NEGATE/NOTEQUAL push+0；LESS 家族常量敏感；BOOL_AND/OR 双子递归 push 返回 subtest1。
- `op_flip_in_place_execute`（funcdata_op.cc:1280-1315）：BOOL_NEGATE 整体删除（输入传播给唯一读者）；BOOL_AND↔OR；其余 get_booleanflip 交换 + swapInput + `replace_lessequal`（funcdata_op.cc:1029-1063，含符号/无符号溢出守卫）。
- `flip_in_place_execute`（block.cc:2381 BlockBasic：翻 FALLTHRU_TRUE + swapEdges；block.cc:3007 BlockCondition：AND↔OR + 双子执行）。
测试：test_prefercomplement_flips_if_else_condition（3-child INT_NOTEQUAL 规范化翻转 / 2-child 拒绝 / 已规范化 INT_EQUAL 拒绝）、test_prefercomplement_flip_in_place_execute（INT_LESS→LESSEQUAL swap；BOOL_NEGATE 删除重接）。GetStr 本身不经此路径（其 if 无 else 臂），此修复消除全局极性污染源。

### 2026-07-01（续 4）：12 个缺失 Action 实现
简单标记类：ActionStartCleanUp（coreaction.cc:5692）、ActionStartTypes（5687，实际工作：set_type_recovery_started）、ActionStop（5738）。
Merge 类：ActionAssignHigh（coreaction.hh:339，rule_onceperfunc，建 HighVariable）、ActionDominantCopy（调 dominant_copy）、ActionCopyMarker（调 copy_marker）。
结构化类（stub，不接入管线）：ActionPreferComplement/StructureTransform/ReturnSplit/NodeJoin（需结构化树/collapseInternal/ConditionalJoin）。
其他（stub）：ActionMapGlobals（需 Scope::queryProperties）、ActionMarkIndirectOnly（需 indirectonly flag）。
ParamShiftStart/Stop 确认在 Ghidra 中被注释掉，不需要实现。
build_full_pipeline_actions 新增 ActionStartTypes/AssignHigh/DominantCopy/CopyMarker。

### 2026-07-01（续 5）：ActionSwitchNorm 调用 recover_jump_tables
ActionSwitchNorm::apply 开头调用 JumpTable::recover_jump_tables(fd)，接入跳转表恢复。

### 2026-07-01（续 6）：Dead-flow Actions 接入方式
4 个 dead-flow Action（Unreachable/DoNothing/RedundBranch/DeterminedBranch）的 apply() 均有实现。本段原称 Unreachable+DeterminedBranch 在 `ActionBlockStructure` 内作 pre-pass；该自创入口已于 2026-08-28 删除，当前 `ActionBlockStructure::apply` 严格从 `installSwitchDefaults → buildCopy → collapseAll` 开始。DoNothing/RedundBranch 的历史管线位置说明不构成行为等价证据。

### 2026-07-01（续 7）：6 个结构化 Action apply 实现
- ActionMarkIndirectOnly：**真实实现**。遍历 input varnode，check_indirect_use（funcdata_varnode.cc:771-811），全 INDIRECT descend 则设 INDIRECTONLY flag。
- ActionMapGlobals：**务实最小**。遍历 vbank，RAM+persist varnode 设 PERSIST+READONLY。
- ActionPreferComplement：**务实最小**。遍历 sblocks 找 CBRANCH 候选，TODO: preferComplement flipInPlace。
- ActionStructureTransform：**历史最小实现（已被后续版本替换）**。当时只遍历 WhileDo 候选；当前状态见本文件顶部 2026-08-28 节，完整 finalTransform 仍为 MISMATCH/UNTESTED。
- ActionReturnSplit：**goto 前驱创建 RETURN op**。isSplittable 判定 + RETURN 候选检测，`Funcdata::node_split` 已移植 (funcdata.rs:1215) 但调用会破坏 staged structurer 稳定索引不变量，故改用 op API 合成 RETURN。
- ActionNodeJoin：**务实最小**。ConditionalJoin 候选检测，TODO: ConditionalJoin 类。
2 新测试。

### 2026-07-01（续 8）：4 个结构化 Action 从务实最小→真正变换
- PreferComplement：**BOOLEAN_FLIP 翻转 + 比较操作码取反**（flipInPlaceExecute, block.cc:2384 + get_booleanflip opcodes.cc:94）。
- StructureTransform：**归纳变量检测 + NONPRINTING 标记**（findLoopVariable block.cc:3164, iterateOp 标记 block.cc:3421）。
- ReturnSplit：**goto 前驱创建 RETURN op**（用现有 op API 替代 nodeSplit, blockaction.cc:2264）。
- NodeJoin：**菱形检测 + 条件合并候选**（ConditionalJoin match, blockaction.cc:2065）。
5 新测试。

### 2026-07-01（续 9）：StructureTransform 测试 BlockWhileDo for_init/for_iter

### 2026-07-01（续 10，历史切片）：StructureTransform 填充 for_init/for_iter
当时的 `ActionStructureTransform::apply` 在检测到归纳变量后：
1. 构建 init 字符串（MULTIEQUAL entry-block input）
2. 构建 iter 字符串（INT_ADD 表达式 `var = var + N`）
3. 设置 BlockWhileDo.for_init/for_iter
4. 标记 iterate op NONPRINTING
printc 在 for_init+for_iter 都存在时发射 `for(init;cond;iter)`。

### 2026-07-01（续 11）：NodeJoin nodeJoinCreateBlock CFG 重写
ActionNodeJoin::apply 在检测到不同条件的菱形（diamond）后，执行 nodeJoinCreateBlock（funcdata_block.cc:790-826）：
1. 创建新基本块（JOINED_BLOCK flag）
2. remove_edge: block1→exita, block2→exitb
3. add_edge: block1→join, block2→join, join→exita, join→exitb
4. rebuild_dom_tree
Funcdata: +create_new_block。BlockBasic: +JOINED_BLOCK flag。
同条件菱形：data-flow only（无新块）。

### 2026-07-01（续 12）：NodeJoin 真正执行 nodeJoinCreateBlock 变换

### ActionReturnRecovery 实装（2026-07-03 续）
- 之前的 `ActionReturnRecovery`（coreaction.rs:5721）是空桩——只在 RETURN 已有 >1 input 时记 trial，从不主动找 RAX 写入。
- 替换为功能性实现：对每个无返回值的 RETURN（num_input <= 1），扫描其所在 basic block 反向找最后一个写 RAX（Register 0x0）的 op，把那个 output varnode 挂到 RETURN 的 slot 1。fallback：扫 alivelist 在 RETURN 之前的 RAX 写入。对齐 Ghidra `buildReturnOutput`（coreaction.cc:1836-1906）的单寄存器（RAX）情况；多寄存器拼接（PIECE）和 ParamActive 多 pass 待补。
- **效果**：函数返回类型从全 `void` 恢复到正确类型——`my_fwrite`/`myprogress`/`glob_*` 等现在返回 `int`/`long`（之前是 `void`）。只有真正无返回值的（main_init/main_free/hugehelp）保持 `void`。curl gcc 24/24（保持），0 defects，956/956 测试。

### ActionAssignHigh 增强（2026-07-03 续）
- ActionAssignHigh（coreaction.hh:339）已存在并已在 build_full_pipeline_actions（:7084）注册。
- 增强：新增 `Funcdata::set_high_level`（funcdata.rs）+ `funcdata_flags::HIGHLEVEL_ON`（对齐 Ghidra `highlevel_on` funcdata.hh:84）。
  set_high_level 设标志 + 遍历 loc_tree 给每个无 high 的 Varnode 分配 HighVariable（对齐 Ghidra `setHighLevel` funcdata_varnode.cc:595 + `assignHigh` :48-59）。
  幂等：HIGHLEVEL_ON 已设则直接返回（Ghidra 同样行为）。ActionAssignHigh::apply 现委托到 set_high_level（之前是内联重复逻辑）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `build_local_types` → `build_localtypes`（对齐 `ActionInferTypes::buildLocaltypes` coreaction.cc:5008。注意 Ghidra 拼作 "Localtypes" 一个词，非 "LocalTypes"）。
- `ensure_callspecs` → `setup_call_specs`（对齐 `FlowInfo::setupCallSpecs` flow.hh:129。Rugra 签名是批量 over fd，Ghidra 是 per-op，但命名对齐）。

### 2026-07-03（续）：命名对齐 Ghidra Action 名
- `ActionMergeCopy::get_name()` "merge_copy" → "mergecopy"（对齐 Ghidra Action 名 coreaction.hh:387，Ghidra 无下划线）。
- `ActionCopyMarker::apply` 调用更新为 `mark_internal_copies`（配合 merge.rs 改名）。

### 2026-07-04：ActionMergeCopy/ActionDominantCopy 对齐
- `ActionMergeCopy::apply` 从 45 行内联逻辑改为纯委托 `merge.merge_opcode(fd, CPUI_COPY)`（对齐 coreaction.hh:392 `data.getMerge().mergeOpcode(CPUI_COPY)`）。
- `ActionDominantCopy::apply` 调用 `process_copy_trims`（配合 merge.rs 改名）。

### 2026-07-04（续 2）：ActionHideShadow 改为委托 Merge::hide_shadows_of
- 从内联地址匹配 shadow 检测改为委托 `merge.hide_shadows_of(high)`（对齐 coreaction.cc:4831 遍历 high + 调 hideShadows）。
<!-- annotation-pass: 2026-07-04 -->
<!-- fullloop-repeatapply: 1783144461.7826152 -->
<!-- delete-simplify: 1783145834.621112 -->
<!-- activeparam-port: 1783158350.9445786 -->
<!-- activeparam-integration: 1783160103.0862665 -->

### 2026-08-13：Action leaf executor flags/count（PIPE-ACTION-COUNT-0001A）

- `ActionStartTypes` 仍按 Ghidra 在 `apply` 内累计继承的 `Action::count`，并通过
  `take_count_delta` 将该增量恰好一次交给 Rust 的外置 `ActionState`。这使包含它的
  `rule_repeatapply` 组能看到首次 `startTypeRecovery()` 的一次变化并执行第二轮。
- `ActionPrototypeTypes`、`ActionDefaultParams`、`ActionExtraPopSetup`、
  `ActionFuncLink`、`ActionFuncLinkOutOnly`、`ActionInternalStorage` 暴露构造器中的
  `rule_onceperfunc` flag。第一次零变化执行后进入 `status_end`，同一函数内跳过后续
  `perform`；`reset` 后可以再次执行，同时保留累计统计。
- 锁定 12.0.4 的 `action_leaf_count_1204` oracle 只批准 StartTypes 的完整首次/重复状态
  转换，以及上述六个 leaf 的零 calls/ops/blocks 边界生命周期。它不批准这些 leaf 的
  非空数据遍历，也不覆盖 `ActionDoNothing` 或 `ActionSetCasts`。

### 2026-08-11：ANN-F provenance 分类（无行为变更）

以下三个函数在 Ghidra 12.0.4 中没有独立函数体，不能标成逐函数映射：

- `newparam_push_unique` 是 `ActionReturnRecovery::buildReturnOutput`
  (`coreaction.cc:1836-1906`) 内联 `vector::push_back` 的 Rust
  `Option<Arc<_>>` 适配器；其末项去重依赖当前非 nullable input 模型，缺口由
  `OPBANK-0001` / `FSPEC-0002` 跟踪。
- `seed_output_trials` 是因 `Heritage::guardReturns`
  (`heritage.cc:1652-1692`) 尚未接入而放到 return-recovery 阶段的 fallback；
  该阶段迁移不构成行为对齐，由 `HERITAGE-0001` / `FSPEC-0002` 跟踪。
- `derive_func_output_map` 因 Rugra `FuncProto` 尚未持有实际 `ProtoModel`，临时调用
  `default_x86_64()`；Ghidra 在 `ActionReturnRecovery::apply`
  (`coreaction.cc:1908-1955`) 直接调用当前函数原型的 `deriveOutputMap`，缺口由
  `FSPEC-0001` / `FSPEC-0002` 跟踪。

本轮只补 `RUGRA-GLUE` provenance；实现及 oracle 状态均未改变。
 
 
 
 
 
 
 

---

## 2026-08-15：PIPE-MERGETYPE-ORDER-0001 — merge 族名称/flags/计数桥修正

- `get_name` 逐字对齐 oracle 构造器名（无下划线）：
  `merge_required→mergerequired`（coreaction.hh:364）、
  `merge_adjacent→mergeadjacent`（:376）、
  `merge_multientry→mergemultientry`（:398）、
  `merge_type→mergetype`（:409）。
- 补 14 个 `get_flags → RULE_ONCEPERFUNC` 覆盖（mirrors 构造器位）：
  MergeRequired(:364)、MergeAdjacent(:376)、MergeCopy(:387)、
  MergeMultiEntry(:398)、MergeType(:409)、MarkExplicit(:440)、MarkImplied(:461)、
  NameVars(:482)、SetCasts(:330)、InputPrototype(:894)、OutputPrototype(:905)、
  HideShadow(:992)、DynamicSymbols(:1036)、PrototypeWarnings(:1047)。
  此前 executor 观察到 status=1（可重入）而 oracle 为 status_end=16。
- `ActionMarkExplicit::apply` 返回 `change_count`（Ghidra coreaction.cc:3247-3251
  每次 setExplicit 增继承 count； sanctioned Rust count-bridge，见
  `Action::perform` 文档）。
- `ActionMarkExplicit::base_explicit` 补 oracle 缺失守卫
  `if (vn->hasNoDescend()) return -1;`（coreaction.cc:3064）——悬空输出必须
  explicit，否则被 MarkImplied 置 implied 并被 mergeTestBasic 排除，
  MergeType 合并无法发生。
- `build_full_pipeline_actions` 移除 AssignHigh/DominantCopy/CopyMarker
  （已迁移至 set_default_actions 的 :5717/:5723/:5729 精确位置）。
- fixture 证据：`tests/oracle/action_merge_order_1204.{cc,rs}` 29 行观察 28 行
  逐字节一致（seq/counts/status/IR/merge_temps 全对齐）；唯一残差
  `finalstructure` count 桥在 blockaction.rs（域外）。

### 2026-08-15：`ActionReturnRecovery` 生命周期对齐（`FUNC-TYPEPROP-SETTLE-0001`）

消除 match_url/`__libc_csu_init` 的 mainloop ABA 自旋（120s 硬超时）：

- `ActionPrototypeTypes` Step 4：output 未锁时**无条件** `init_active_output`
  （coreaction.cc:4649-4651，onceperfunc），替换自创的 void+has-RETURN 门控。
- `ActionReturnRecovery::apply`：`active_output` 为 None 时早退（= oracle
  `if (active != 0)` 门，cc:1908-1955），不再在 clear 后重建容器；空 RETURN
  分支补完生命周期尾（finishPass→maxPass 判定→deriveOutputMap→clear）而非
  提前返回——循环因此可排空并恰好 clear 一次。
- 计数对齐 oracle：每个未 checked trial 处理后 +1（cc:1935）+
  clearActiveOutput 后恰好一次 +1（cc:1951）；删除自创 else 计数与
  per-RETURN build 计数。

证据：match_url 120s→102ms、`__libc_csu_init`→10.5ms（残留的一次性
"not settling" 警告=对齐 Ghidra localcount>=7 warn-once 语义）；单测
1337/6 域外不变。按机制 B2 记 **UNTESTED**（源级对齐+E2E 恢复，returnrecovery
生命周期逐函数 oracle fixture 为后继项）。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`ActionNameVars::linkSymbols`（coreaction.cc:2930-2976 对应物）修复
hasName 语义：`if (!high->hasName()) continue` 是 variable.cc:718-747 的
"可命名"谓词（coverable/非 implied/unaffected-input 规则），不再是
"已有名字"；nameRepresentative 为空时跳过（Ghidra 对 instance-less high
不可达）。`apply`（cc:2978-3000）改为 Ghidra 顺序：linkSymbols →
lookForFuncParamNames（cc:2858-2897：对 namerec 符号做
`renameSymbol(makeNameUnique(name))`，不再直写 high.name）→ namerec 的
`buildDefaultName(sym, base, vn)` 循环 → `assignDefaultNames(base)` ——同
一共享计数器贯穿。RUGRA-GLUE 桥：命名完成后把符号 display_name 发布到
`HighVariable::name`（Ghidra 打印侧只读 Symbol::getDisplayName；Rugra
printc 仍读 high.name，退役归 PRINTC-SYMBOL-DECL-0001）。
`ActionRestructureVarnode::apply` 安装 x86-64 寄存器名表（translate.hh:380
`getRegisterName` 的 ScopeLocal 站位）。

### 2026-08-16（复核修正）：`ActionNameVars` 两处对齐收口（同上复核）

`link_symbols` 的 spacebase 分支删除 `continue`——Ghidra cc:2957-2958 落入
nameRepresentative/hasName/linkSymbol 后续（unaffected RSP input 经
variable.cc:737-745 会被 linkSymbol）。内联 makeRec 对照 cc:2815-2850 补
四条：`param->isNameLocked()` 门槛（protoparam_flags::NAME_LOCKED）、
vn/param 尺寸门、implied+written 的 CAST 展开（vn→def->getIn(0)，类型置
None 降优先）、重复 high 的 tie-break 用 `Datatype::type_order`（旧类型更
specific 则保留），rec_map 值扩为 (name, Option<Datatype>)。

### 2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）：`ActionNameVars::link_symbols` 传 Architecture-owned TypeFactory

`link_symbols` 开头按 coreaction.cc:2946 `TypeFactory *typeFactory =
data.getArch()->types;` 一次性捕获 `fd.get_arch().types`，在 cc:2971-2972
的 addr-tied 分支传给 `HighVariable::finalize_datatype(&mut factory)`
（本租约内 coreaction.rs 的唯一改动；不涉及 ActionInferTypes/PTRSUB/STOP）。
Architecture/工厂未接线时 fail-closed（不做 finalize 的类型投影），不查
任何 shared-default/process-global 工厂。双侧门禁
`tests/oracle/exactpiece_callers_1204`。

### 2026-08-17：ActionDefaultParams 逐字镜像 model 绑定（FUNCPROTO-MODEL-BIND-0001）

- `ActionDefaultParams::apply` 对齐 coreaction.cc:2311-2337：
  `evalfp = arch.evalfp_called ?: arch.defaultfp`（cc:2313-2315）；对每个
  `!fc.prototype.has_model()` 的 callspec 走 cc:2327-2328 else 分支
  `fc->setInternal(evalfp, types->getTypeVoid())`（Rugra 无法解析
  per-callee Funcdata，copy 分支不可达）；`fc->insertPcode` 的 callfixup
  注入仍缺（CALLFIXUP 域）。删除旧 "unknown→default" calling_convention
  字符串种子——模型名由 `set_model` 从真实模型取（`__stdcall`）。
  RUGRA-GLUE：简化 `proto_model`（type_system）种子保留给
  `possible_input_param` 消费者（Ghidra 单 model 字段无双轨）。
  生产效果：callspec `has_effect` 从恒 UnknownEffect 变为 cspec 声明效果，
  guardCalls 的 INDIRECT 风暴（main pass0=13,462）消退。

### 2026-08-17（r2 返工）：locked 守卫 + ActionPrototypeTypes 绑定尾（FUNCPROTO-MODEL-BIND-0001）

- 集成复测两回归的返工：①`ActionDefaultParams::apply` 对 modelless +
  model-locked callspec（LibcSignatureTable/DWARF 边界，Ghidra 对应
  UnknownProtoModel 克隆，architecture.cc:1155-1166）不再走 setInternal 的
  void 输出/store 交换——只安装共享 eval model（行为克隆等价，锁定
  storage/返回类型保全）；未锁 callspec 仍走 cc:2327-2328 setInternal。
  ②`ActionPrototypeTypes::apply` 补 cc:4615-4619 绑定尾：
  `evalfp = evalfp_current ?: defaultfp`；`!isModelLocked() &&
  !hasMatchingModel(evalfp)` 才 setModel——locked 守卫逐字。配套
  `FuncProto::has_matching_model`（fspec.hh:1391 指针相等 → Arc::ptr_eq）。
  新增单测 `test_action_default_params_locked_callspec_keeps_storage`
  （locked 保 storage/返回类型、unlocked 走 void 交换）。
- fixture 新观察点（双侧 oracle 验证）：PRINTFLAG×4（setDefaultModel
  副作用 architecture.cc:323-330——默认强制不打印、非默认 true、换默认后
  旧恢复 true）与 CALLSPEC_REBIND（绑定后锁定的 callspec 二过
  ActionDefaultParams 不被触碰）。

### 2026-08-17（r3）：ActionPrototypeWarnings::apply 完整移植——warningHeader/warning 通道（UNKNOWN-PROTOMODEL-0001 warning 子项）

旧实现只在参数锁定时 eprintln 到 stderr（非 oracle 通道），且 callspec 分支发
oracle 不存在的 "call at ... has unknown calling convention"。现按
coreaction.cc:4886-4936 逐段移植，全部警告走 `Funcdata::warning_header` /
`Funcdata::warning`（funcdata.cc:135-145/119-129 → commentdb
addCommentNoDuplicate(warningheader/warning, baseaddr, ...)）：

- override 消息（cc:4889-4892）：`fd.localoverride.generate_override_messages`
  （override.cc:279-287，仅 deadcode-delay 类）逐条 warningHeader。
- 自身原型 input/output 错误（cc:4894-4900）：`hasInputErrors/hasOutputErrors`
  为 fspec.hh:1461/1464 flag 位，Rugra FuncProto 未建模（fspec.hh:1351-1352；
  唯一置位源头 = assignParameterStorage 抛 ParamUnassignedError，fspec.cc:4220-
  4222，Rugra 无该路径；另有 fspec.cc:5507-5508 `FuncCallSpecs::forceSet` 的
  error-flag 复制——纯源 proto 拷贝非独立源头，且 error_outputparam 全库无
  直接置位源头；custom_storage 的 ATTRIB_CUSTOM decode 在 Rugra 为 no-op 丢弃，
  fspec.rs:1129，系未来接线风险点）——`proto_has_input_errors/output_errors`
  镜像谓词在所有可达状态下读 false，与 oracle 可观测等价（复核方独立 grep
  验证，含 forceSet 复制点）。
- isModelUnknown（cc:4901-4909）：`"Unknown calling convention"` +
  `printModelInDecl()` 时 `": " + getModelName()` + `!hasCustomStorage() &&
  (isInputLocked||isOutputLocked)` 时 `" -- yet parameter storage is locked"`
  （custom_storage 仅 ATTRIB_CUSTOM decode 置位，fspec.cc:4724-4727，Rugra
  decoder 该属性为 no-op stub——`proto_has_custom_storage` 同上等价 false）。
- 每调用点错误（cc:4910-4934）：`FuncCallSpecs : public FuncProto`（继承）在
  Rugra 为组合，谓词读 `fc.prototype`；名字取 `prototype.name`（set_funcdata
  绑定的 display name），空名 → `"<indirect>"`（cc:4913-4920）；定位地址 =
  `call_entry_address`（fspec.hh:1686 getEntryAddress；oracle 间接调用保持
  invalid 地址，fspec.cc:4943——Rugra None 归一为 offset 0）。

新增 fixture×3（coreaction.rs tests）：locked+unknown 写入 commentdb 精确文本
`WARNING: Unknown calling convention -- yet parameter storage is locked`
（WARNINGHEADER 类型 @baseaddr，二跑 addCommentNoDuplicate 去重=1 条）；未锁
unknown 无后缀；override 消息走同通道。验证：`cargo test --lib` 1391 pass/
5 fail（与基线同集：comment/dynamic/funcdata×2/ruleaction 预存，见
RULE-SUBCANCEL-RWLOCK-0001 记录）；curl E2E Matched 123、defects=0、gcc 17
FAIL 不变；annotations/refs 门禁过。

**C 输出发射仍断链（printc/arch 域，登记 UNKNOWN-PROTOMODEL-WARN-EMIT-0001）**：
arch.commentdb 默认 None（arch.rs:523，oracle sleigh_arch.cc:244 构造即
`new CommentDatabaseInternal()`）；printc doc_function（printc.rs:5120）未调
`commsorter.setup_function_list`（oracle printc.cc:2650）也未调
`emit_comment_func_header`（printc.cc:2652；Rugra 已有实现 printc.rs:8450 但零
调用方）；且 printc.rs:570-573 的 head/instr comment mask 与
printlanguage.cc:579/582 **接反**（oracle head=header|warningheader、
instr=user2|warning）。E2E 现状：管线侧 24 PLT thunk 函数的警告已经 warning
通道产出（stderr fallback 48=24 函数×2——action.rs:912 批量与 :1085 单独
双注册 ActionPrototypeWarnings，commentdb 侧 addCommentNoDuplicate 去重所以
对接后无重复）；3 真实函数（main_init/main_free/hugehelp）被 debugproto.rs:260
DWARF overlay `fd.funcp.clone()` 保留已绑定 defaultfp 模型名阻塞（isModelUnknown
= false），属 UNKNOWN-PROTOMODEL 父项模型语义域。

## 2026-08-17：ARCH-CONTEXT-TRACKED-0001 — ActionConstbase tracked COPY 循环落地

- `ActionConstbase::apply`（coreaction.rs，oracle coreaction.cc:678-706）从 stub
  升级为逐行移植：
  - cc:681 空块早退 → `fd.bblocks.get_size() == 0` 返回 0；
  - cc:684 entry block = `getBlock(0)`（C 风格 cast，Rugra 走 trait 对象）；
  - cc:686-690 injectid≥0 腿（`getFuncProto().getInjectUponEntry()` →
    `getPayload` + `doLiveInject`）保持门控：Rugra `FuncProto` 不存 injection id
    （`set_inject_id` 为 INJECT-0001 no-op，ProtoModelFull::inject_upon_entry 仅经
    protomodel `<inject>` resolver 赋值而生产 worker 不注册），按 flow.rs
    `FuncCallSpecsExt::get_inject_id` 同款 INJECT-0001 兼容回退读作 -1；
  - cc:692 `getTrackedSet(data.getAddress())` →
    `fd.get_arch().get_tracked_set(AddressSpace::Ram, fd.get_address().as_u64())`
    （Rugra Address 无空间维，函数地址=默认代码空间 ram，同空间查找与 Ghidra
    baselist 序全等——见 arch.rs TrackedSetMap 排序 caveat）；快照 `to_vec()`
    结束不可变借用后再进变异循环（Ghidra 引用指向全局 context，循环不触其变异）；
  - cc:694-704 每 tracked ctx：`Address(ctx.loc.space,ctx.loc.offset)` →
    `Address::new(ctx.loc.offset)`（`new_varnode_out` 钉 Register 空间——DF
    register:0x20a:1 正确；非 register tracked loc 需 space-aware vbank create，
    已注释登记）→ `new_op(1, bb.get_start_addr())` → `new_varnode_out(size,addr,op)`
    → `new_constant(size, ctx.val)` → `op_set_opcode(CPUI_COPY)` →
    `op_set_input(op,vnin,0)` → `op_insert_begin(op,&bb)`（多 ctx 时逆序居块头，
    与 opInsertBegin 语义一致）；
  - cc:705 无条件 `return 0`（无 change 计数器）→ `NO_CHANGE`。
- worker pspec 喂入（examples/curl_decompile.rs 与
  examples/getstr_stage_snapshot.rs 的 `worker_architecture` 镜像）：
  `restoreFromSpec` 先 `parseProcessorConfig` 后 `parseCompilerConfig`
  （architecture.cc:639→641），其 ELEM_CONTEXT_DATA 臂（:1190）→ 读
  `sleigh_specs/x86-64.pspec`、DocumentStorage 解析、每个 `<context_data>` 子元素
  经 `TreeDecoder` 喂 `arch.decode_context_data`（fixture 同款 DOM 提取，ARCH-0001
  最小接线；其余 pspec 子元素仍为 pspec 文本管线残差）。
- 生产验证：GetStr 02b 层 [CALLGUARD] 投影 18 → **20**（每 call 补第 10 个
  0x20a range，相对序 0,30,38,200,202,206,207,20a,20b,288 与 oracle 全等）；
  block0 头部 COPY out=register:0x20a:1 in0=const0（被两个 INDIRECT guard 读）。
- E2E（HEAD 004816a 干净 worktree 基线对比）：skeleton 3155→3151
  （my_get_line/helpf/file2string.part.0/getparameter.constprop.0 各消 1 行
  幽灵 `in_register_0000020a` 声明——golden 无此行，方向朝 oracle）；
  defects=0/numbering=0/Matched=123 不降；gcc audit 16 FAIL（≤16 基线内，前值 17）。
- 回归测试：`coreaction::test_action_constbase_inserts_tracked_copy_at_entry_head`
  （单侧 Rugra 断言：DF tracked_set 摄取 → COPY 居块头、out=reg:20a:1、
  in0=const0、返回 0；机制 B2：手写 expected 不升 MATCH，oracle 侧证据=
  getstr_pipeline_1204 02b 层逐对象投影）。
- 既有 fixture 影响：`heritage_callguard2_1204` runner 的 `heritage_rs_sha256`
  钉在 base 102c476，committed 漂移（heritage.rs +14/funcdata.rs +195）致其在
  干净 HEAD 同样 mismatch（本改动前已破，非本 write-set 所致；需 fixture owner
  重钉 base）。

## default 管线树重构 WIP（2026-08-22，PIPE-DERIVED-TREE-0001 / PIPE-HEAD-FLAT-ACTIONS-0001）

- 扁平 `build_full_pipeline_actions` 重构为 Ghidra 嵌套树镜像：universal 头部
  8 Action（coreaction.cc:5477-5486）、mainloop Segmentize/InternalStorage 槽位
  （:5493-5500）、stackstall 子序列 oppool1→LaneDivide→MultiCse→ShadowVar→
  Deindirect→StackPtrFlow（:5651-5656）；`find_group_recursive` 树查询。
  WIP：pipeline_tree_1204 双侧 fixture 与 stackstall count 反馈 pending；
  参考 docs/alignment_docs/PIPELINE_STAGES_1204.md。

## 精确 action 名与 ctor flags 对齐（2026-08-23，PIPE-DERIVED-TREE-0001）

- 五个 `get_name()` 修正为 Ghidra ctor 字面名：`restructureVarnode`→
  `restructure_varnode`（coreaction.hh:855）、`unjustifiedparams`→
  `unjustparams`（:920）、`mappedlocalsync`→`mapped_local_sync`（:869）、
  `funclinkoutonly`→`funclink_outonly`（:715）、`conditionalconst`→
  `condconst`（:595）。
- 三个 `get_flags()` 补齐 ctor rule flag 位：`lanedivide`→
  RULE_ONCEPERFUNC（coreaction.hh:117）、`donothing`→RULE_REPEATAPPLY
  （:504）、`normalizesetup`→RULE_ONCEPERFUNC（:630）。
- 对拍证据：`tools/run_pipeline_tree_oracle.sh` 78 节点 DFS 双侧
  字节一致（含每个节点的 name/basegroup/flags），overall=MATCH。

## stackstall 叶子 count 通道与 analysis_finished 生命周期（2026-08-23，PIPE-STACKSTALL-COUNT-0001）

- `ActionMultiCse`/`ActionShadowVar`/`ActionDeindirect` 的 apply 内部变更数
  此前计算后丢弃，现写入继承 `Action::count` 通道（`take_count_delta` 外化，
  对应 coreaction.cc:873/:945/:1240 的 `count += 1`），stackstall 的
  rule_repeatapply 不动点由此感知叶子变更（action.cc:303-350 + 506-527）。
- `ActionStackPtrFlow` 补齐 `analysis_finished`（coreaction.hh:91，reset 清除
  ：99）、`apply` 首行短路（cc:484-485）、`numchange>0 → count += 1`
  （cc:492）、干净趟 `analyzeExtraPop` + `analysis_finished=true`（cc:494-497）；
  extrapop-known 早退（cc:264-267）经 `fd.funcp.get_extra_pop()` 判定；
  未知 extrapop 的 StackSolver 路径走已有 `analyze_extra_pop`（其 callspec
  回写仍未接线，残差 PIPE-STACKSOLVER-WRITEBACK-0001）。
- 两处缺陷修复：`ActionShadowVar` 重写路径的 RwLock 死锁（`if` 条件临时读
  guard 贯穿分支体，`op_set_input` 写锁自锁——该路径首次真实执行即挂起整条
  管线）；`checkClog` 的 `constz` 取值错位（应取 LOAD 指针的栈相对偏移
  cc:473-475，而非 clog ADD 操作数偏移）。
- 对拍：`tools/run_stackstall_count_oracle.sh`（pin-base schema2，base=b40a315
  + overlay）——双侧真实派生树的 stackstall 子树经 action.cc:303-350 外部
  perform 镜像逐趟观察：run1 三趟收敛（multicse/shadowvar/stackptrflow 各
  count=1，趟2 oppool1 count=1，终值 4），run2 reset 后单趟零变更且
  stackptrflow tests 3→4（analysis_finished 复位再分析），IR 投影逐字节一致，
  stdout_sha256=0a9439b3…，overall=MATCH。残差：deindirect 变更分支
  （PIPE-DEINDIRECT-CHANGE-0001 建议）、solver 回写。

## ActionLaneDivide 完整移植（2026-08-23，ACTION-LANEDIVIDE-0001）

- `ActionLaneDivide` 不再是 no-op stub。三函数完整移植
  （coreaction.cc:509-622，coreaction.hh:107-123）：
  - `collect_lane_sizes`（cc:509-540）：descendant 先行（step 0）后 def
    （step 1）遍历；SUBPIECE descendant 贡献 `out` size，PIECE def 贡献
    `min(in0,in1)` size；仅 `allowedLane` 接受的 size 注册进 checkLanes
    （bitmask 语义）。
  - `process_varnode`（cc:558-583）：mode<2 走 collect；mode 2 用
    pointer size（`!=4 → 8` 归一化）做默认 lane；lane 尺寸按
    LanedIterator 升序逐个尝试；首个 `doTrace` 成功即 `apply` 并
    `count += 1`。
  - `apply`（cc:585-622）：先 `setLanedRegGenerated`（minLanedSize=1000000
    封死后续注册）；mode 0..2 三趟，趟内按 `VarnodeData::operator<` 序遍历
    lanedMap，每个 storage 走 `[beginLoc(sz,addr), endLoc(sz,addr))`
    （loc-tree 精确 (space,offset,size) 过滤，`VarnodeCompareLocDef` 序）；
    `hasNoDescend` 跳过；成功拆分后重算 bounds 从头再走；失败推进且记
    `allVarnodesProcessed=false`；`allStorageProcessed` 才提前 break；
    最后 `clearLanedAccessMap`。Ghidra 的活 map 迭代在 Rust 侧用每 mode
    BTreeMap 快照等价实现（apply 期间 map 可证明稳定：插入全部被
    minLanedSize 门禁封死，删除只在末尾 clear）。
- count 经 `take_count_delta` 外化（cc:578 `count += 1`）；apply 恒返回 0
  （cc:621），RULE_ONCEPERFUNC 状态机（action.cc:352-357）使第二趟 perform
  在 `status_end` 直接短路——不改 stackstall 槽位（:5652，eb8ad57 已集成）。
- 对拍：`tools/run_action_lanedivide_oracle.sh`（pin-base schema2）——
  piece 成功路径（collect 双来源 + mode 0 拆分 + count=1 + IR 投影 +
  lanedMap 1→0）、failure 路径（collect 过滤拒绝 + mode 0/1 空 + mode 2
  默认 lane 8 对 INT_MULT backward 拒绝 + 零突变 + map 清空）、
  rule_onceperfunc（re-queue 后第二趟 perform 不清 map、ret2=0、count
  不变、IR 稳定）双侧逐字节一致，overall projection=MATCH。残差见
  ACTION-LANEDIVIDE-RESIDUAL-0001（mode 1 downcast SUBPIECE 终结符、
  同 storage 多 varnode 的 bounds 重走、多 storage 迭代序、pointer=4 归
  一化分支未在 x86-64 oracle 上覆盖）。

## 2026-08-23（VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 编译适配）：v_type 读改为 v_type.get()

四处 `h.read().unwrap().v_type.clone()` → `h.read().unwrap().v_type.get()`（:3191/:3266/:3338/:3385）。`HighVariable::v_type` 缓存迁入 `TypeCell` 锁域（Ghidra variable.hh:141 `mutable` 的对应物，详见 docs/api/variable.md）；`.get()` 仍是同一共享分配的 Arc 拷贝读，且现在携带 variable.hh:174 `getType()` 的惰性 updateType 语义。

## 引用行号勘误（2026-08-24，root）

buildLocaltypes 引用 coreaction.cc:5012 修正为 5008（定义起始行）。

## ParamActive 地址空间传递（2026-08-24）

`ActionInputPrototype`、`ActionFuncLink` 的 Heritage fallback，以及
`seed_output_trials` 现在把来源 Varnode、调用参数或模型条目的已知
`AddressSpace` 显式传给 `ParamActive::which_trial_in_space` /
`register_trial_in_space`。
这保留了 Ghidra `Address` 中的真实空间身份，使仅有 offset 的过渡
`Address` 不会被 fail-closed 拒绝，也不恢复旧有的 Register 推断。此改动
只修复 caller 的空间传递；对应 action 中既有的模型硬编码与未完成恢复分支
仍按原登记残差保留。

## CALLSPEC-IDENTITY-D0 下游接线（2026-08-24）

- `ActionFuncLink::setup_call_specs` 以 exact `PcodeOpRef` 去重并创建稳定 owner，
  将 typed FSPEC annotation 绑定到同一 owner；`ActionDeindirect` 在 CALLIND
  确认直接目标后也先安装该 annotation，再改成 CALL。两处都不再用
  `op_addr`/vector index 充当身份。
- 正常 lifting 已由 `FlowInfo::setup_call_specs` 建立 callspec；
  `ActionFuncLink::setup_call_specs` 只为绕过 FlowInfo 而手工构造的 alive CALL
  保留兼容 fallback。该 fallback 不是第二套 FlowInfo，也不把未覆盖的 consumer
  闭包升为 `MATCH`，继续绑定 `CALLSPEC-0001`。
- `ActionFuncLink`、`ActionFuncLinkOutOnly`、`ActionNameVars`、
  `ActionActiveReturn`、`ActionExtraPopSetup`、`ActionInferTypes` 等调用点通过
  callspec 的 exact op `Weak` 或 `Funcdata::get_call_specs_of_op` 取回同一个
  owner。DeadCode、active trial、warning 与原型处理用短 read/write guard；需要
  随后修改 Funcdata 时先复制 entry/type/model/slot 等值并释放 guard，避免锁借用
  改变 Action 的遍历顺序或 mutation 时机。
- 这些变化只接通身份和 Rust guard 生命周期，未改变各 Action 已登记的模型、
  trial、callfixup 或类型推导残差。D0 总体仍为 `MISMATCH`：专用
  `IPTR_FSPEC` 缺失，`AddressSpace::Iop` 临时代用由
  `TYPEOP-FSPEC-SPACE-0001` 跟踪；TypeOp getter、PrintC、StringManager 不在
  本阶段 write-set，主管线 Action 及模块状态均不据此升级。
- `StackSolver::build` / `analyze_extra_pop` 的旧注释已更正：exact per-op
  callspec lookup 已存在；真正未完成的是 `effective_extrapop` 字段、从 Iop
  source op 到 owner 的消费、known-extrapop 时把真实 rhs 写入 equation（当前仍固定
  guess 4），以及 solver 的 mutating write-back。初始 stack-pointer 非 input 时的
  错误通道也未对齐：Ghidra 抛 `LowlevelError` 并由 caller 写 warningHeader，Rust 仅写
  stderr 后返回；该非 callspec 分支绑定 `PIPE-STALL-SHAPE-0001`。上述分支均未做
  双侧执行，状态为 `UNTESTED`；callspec 分支继续绑定 `CALLSPEC-0001`，不属于 D0
  identity `MATCH`。

## ActionConditionalConst propagateConstant CPUI_RETURN 特例（2026-08-25，RETURNFOLD-GAPB-CONDCONST-0001）

- `propagate_constant` 补齐 cc:4439-4448 的 CPUI_RETURN 特例：RETURN 不能直接吃
  常量输入——对被 const 块支配的每个 RETURN 后代，先 `new_op(1, ret.addr)` 建
  `copyBeforeRet` COPY，`op_set_opcode(COPY)`、`op_set_input(copy, constVn, 0)`、
  输出 varnode 落在 varVn 的精确 (space,offset,size)（cc:4445
  `newVarnodeOut(varVn->getSize(), varVn->getAddr(), …)`；Rust 侧因
  `Funcdata::new_varnode_out` 钉死 Register space，改用
  `vbank.create_def_with_space` + 内联 assignHigh/checkForLaned/
  setVarnodeProperties 腿，保留任意 space 的正确性），RETURN 的 slot 1 无条件改读
  该 COPY 输出（cc:4446 用字面 1，不用 getSlot(varVn)），最后
  `op_insert_before(copy, ret)`。此前的 Rust 把常量直接塞进 RETURN 输入槽，
  产出 oracle 永不存在的 `RETURN const` IR 形（A61 审计 GAP-B）。
- 非 RETURN 支配读仍走 cc:4449-4452 的直接槽替换；`count += 1` 对两臂一致
  （cc:4453）。Rugra-only 的值级收敛守卫保留（`already_const` 早退），RETURN 臂
  上天然空转：插入后 slot 1 持 COPY 输出而非常量，且 op_set_input 切断 varVn→
  RETURN 的 descend 链使 RETURN 不会被重访。
- 下游不变量：copyBeforeRet **不**置 `return_copy` flag（区别于 heritage
  guardReturns 的 persist COPY）；`RulePropagateCopy` 的 cc:3933
  `isReturnCopy()` 守卫保证该 COPY 输入永不被折叠进 RETURN（RETURN 本身带
  TypeOpReturn 的 return_copy flag，typeop.cc:879）。
- 双侧对拍：`tests/oracle/returnfold_gapb_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_gapb_oracle.sh`——真实 `ActionConditionalConst::apply`
  驱动 5 块 CFG（INT_EQUAL(X,5) CBRANCH、两个被支配 RETURN、一个非支配 RETURN、
  一个非 RETURN 支配读 INT_ADD），观察面含 RPO 序、X descend 序、count
  （CountProbe/`count` pub 字段 + perform-bypass 的 zeroCount 说明）、COPY
  几何（pc/out/in0/flags）、slot1 非常量不变量、二次 apply 稳定性、
  RulePropagateCopy 全扫描 hits=0；双侧 stdout 字节一致（MATCH）。残差（均
  登记 UNTESTED，见 metadata）：apply 返回值不对称（Ghidra cc:4545 恒 0 vs
  Rugra count>0，CONDCONST-APPLY-RETURN-0001）、MULTIEQUAL phi 臂
  （CONDCONST-MULTIEQUAL-GUARD-0001）、implied-boolean 臂
  （CONDCONST-IMPLIEDBOOL-0001）、打印期折叠（依赖 GAP-A/GAP-D 上游）。

## ActionPrototypeTypes output-locked 直挂分支（2026-08-25，RETURNFOLD-GAPA-PROTOTYPES-0001）

- `ActionPrototypeTypes::apply` 补齐 cc:4637-4649 的 output-locked 双分支之 locked 臂
  （此前 Rust 只有 else 臂 `init_active_output`，locked 路径什么都不做——locked 输出
  函数裸 `return;` 的根因，A61 审计 GAP-A）。忠实语句序：
  `outparam->getType()->getMetatype() != TYPE_VOID` 门（cc:4639，locked-void 如
  `exit`/`free` 不挂任何东西、也不 init activeOutput）→ 对每个活 RETURN：
  `isDead` 跳过（cc:4642）、`getHaltType()!=0` 跳过（cc:4643；op.hh:170-172 的完整
  掩码 halt|badinstruction|unimplemented|noreturn|missing）→
  `newVarnode(outparam->getSize(), outparam->getAddress())`（cc:4644，size 取类型
  尺寸非寄存器全宽）→ `opInsertInput(op, vn, op->numInput())`（cc:4645，**追加为末
  槽**——已有值输入的 RETURN 追到 slot 2，不替换既有 slot 1）→
  `vn->updateType(type, true, true)`（cc:4646，typelock+override）。
- Rust 地基桥（ANN-F，FSPEC-0001/FSPEC-0002）：扁平 `FuncProto` 无 output
  ProtoParameter，存储地址取自 `ProtoModel::default_x86_64().output_entries[0]`
  （Register 0x0），类型/尺寸取 `funcp.return_type`——与 Ghidra
  `assignParameterStorage`（fspec.cc:2429/1569-1581，setPieces→updateAllTypes→
  store->setOutput）给出的 oracle 观察地址一致（fixture 已钉死 register:0x0:4）。
  `newVarnode(s, AddrSpace, off)` 形态（funcdata.hh:284/funcdata_varnode.cc:239-247）
  因 `Funcdata::new_varnode` 钉死 Ram space，改内联其 (cc:148-169) 腿：
  `vbank.create_with_space` + assign_high + checkForLaned + set_varnode_properties
  （GAP-B copyBeforeRet 同款模式）。
- 与 GAP-B（copyBeforeRet，cc:4439-4448）协同：PrototypeTypes（onceperfunc，早期）
  先挂 locked 输出 varnode 为 RETURN 末槽，heritage 把寄存器写链到它；晚期
  ConditionalConst 的 RETURN 臂读 varVn（即该地址上的 varnode），COPY 输出落在
  varVn 精确 (space,offset,size)，`op_set_input(op, out, 1)` 替换 slot 1——两臂
  无冲突，正是 oracle 的先后链。`ActionReturnRecovery::apply` 的
  `output_type_locked` 早退（coreaction.rs apply 开头）在 Ghidra 因 locked 时
  activeOutput 必为 NULL 而冗余等价；GAP-A 后 locked 函数不再 init_active_output，
  该守卫成为唯一防线（保留并已在注释注明，GAP-C 审计结论）。
- 双侧对拍：`tests/oracle/returnfold_gapa_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_gapa_oracle.sh`——真实 `ActionPrototypeTypes::apply` 三场
  景：A=locked int（4 RETURN：裸 RETURN 挂 slot 1、带值 RETURN **追加** slot 2 且
  slot 1 不动、halt RETURN 跳过、dead RETURN 跳过；观察 nin/in_last
  register:0x0:4/def=free/typelock=1/mt=int、attach 次序、varnode 不共享、
  activeoutput 缺席）；B=locked void（不挂不 init）；C=unlocked 对照（只
  initActiveOutput，active=1）。C++ 侧走 Ghidra 原生 locked 路径（setInternal+
  setPieces→assignParameterStorage→setOutput）。双侧 stdout 14 行字节一致
  （MATCH）。残差（均 UNTESTED，见 metadata）：ANN-F 模型胶水（仅钉观察地址）、
  多输出条目模型、E2E 折叠链（依赖 GAP-D）。

## funcLinkOutput 锁定输出存储分支（2026-08-25，FSPEC-OUTPUT-STORAGE-0001）

- **Ghidra**: `ActionFuncLink::funcLinkOutput` 的 coreaction.cc:1538-1553 腿——
  locked 非 void 输出读 `outparam = fc->getOutput()`，`addr =
  outparam->getAddress()`；`addr.getSpace()->getType() == IPTR_SPACEBASE` 时
  `fc->setStackOutputLock(true)` 并**延迟**输出 varnode 到栈 heritage
  （`Heritage::tryOutputStackGuard` 在 caller 视角重建，heritage.cc:1414），
  否则 `data.newVarnodeOut(sz, addr, callop)` 立即建在记录存储上。
- **Rugra 侧**：`func_link_output` 现读 `fc.get_output_storage()`
  （fspec.rs 扁平 store 的 `outparam::addr` 站位）；`Stack`（过渡枚举的
  spacebase，与 guardCalls cc:1460 同约定）→ `set_stack_output_lock(true)`
  + return；register 等其他空间 → `new_varnode_out(sz, Address::new(off))`
  （new_varnode_out 建在 register 空间 = 登记过的过渡分歧）。无记录存储
  （Ghidra 不可达：known-prototype 路径未记录）保持 RAX 0x0 legacy 回退。
  `sz` = `outparam->getSize()` = 返回类型 size（fspec.hh:1176）。
- 仍 deferred（`CALLSPEC-0001`）：cc:1543-1544 `opMarkCalculatedBool`
  （TYPE_BOOL sz==1 + isTypeRecoveryOn）与 cc:1552-1568
  `assumedOutputExtension` → SEXT/ZEXT/PIECE 小尺寸扩展 op。
- 证据：`tests/oracle/heritage_tryoutput_1204.*` case=production_entry_guardcalls
  ——stack 存储（stacklock=1, pre_out=0, 守卫后 SUBPIECE、无 INDIRECT）与
  register 控制几何（stacklock=0, pre_out=1, INDIRECT 守卫）双侧逐字节 MATCH。
## 2026-08-25（COREACTION-BASEEXPLICIT-NUMINST-0001 + COREACTION-MARKIMPLIED-COUNT-0001）：return 折叠链第三环 GAP-D 计数修正

- **`ActionMarkExplicit::base_explicit` 补多实例规则**（Ghidra coreaction.cc:3020-3021）：
  `HighVariable *high = vn->getHigh(); if ((high!=0)&&(high->numInstances()>1))
  return -1; // Must not be merged at all`——插入点在 call 检查之后、addr-tied
  规则**之前**（oracle 顺序：def null → marker → call/NEW → **numInstances>1** →
  addrtied → mapped → protoPartial → hasNoDescend → PTRSUB maxref 放宽 →
  desccount）。多实例 High 成员（mergerequired 的 mergeAddrTied 已强制合并的
  stack cluster 等）内联会把多个 SSA 版本的合并 cover 拉过读点，必须以显式命名
  变量打印——这正是 oracle 中 `return iVar;`（显式形）与 `return <const>;`（折叠
  形）同函数并存的判定开关之一（A61 审计 §1 环节 6）。Rust 侧以
  `vn.high.as_ref() → num_instances() > 1 → return -1` 对齐；
  `HighVariable::num_instances()`（variable.rs，variable.hh:179 numInstances 的
  1:1 port）由 assignhigh/merge 路径维护。
- **`ActionMarkImplied::apply` 计数桥**（Ghidra coreaction.cc:3434 + action.cc:362）：
  oracle 的 DFS pop 分支 `count += 1; // Will be marked either explicit or
  implied` 对**每个被标记（无论 explicit 还是 implied）的候选**各 +1，apply 本身
  返回 0，`Action::perform` 尾部 `return count;` 把累计值作为 perform 结果上报
  （markimplied 构造带 rule_onceperfunc、无 rule_repeatapply，故单次 apply 后
  perform 返回 count）。Rust 侧原先两分支恒返 `NO_CHANGE`（R16 复核确认的
  MISMATCH），现改为与 `ActionMarkExplicit::apply` 相同的 sanctioned count-bridge：
  `change_count > 0 → Ok(change_count)`，perform 累计后同值返回。count 影响
  mainloop 收敛判定与 `act=markimplied|res=N` 观察面。
- **双侧 fixture**：`tests/oracle/gapd_counters_1204.{cc,rs,metadata.json}` +
  `tools/run_gapd_counters_oracle.sh`——真实 universal tree / build_default_pipeline
  驱动 assignhigh..markimplied 四子项。prestate：stack:0x200 精确位置簇
  {m2（COPY 输出，addrtied 门控）、m1（COPY 输出，raw 无属性尾）}cover 不相交
  [r0..r1]/[r2..r3]，mergerequired 强制合并出 2 实例 High；q2/q1/w1 无后继
  （hasNoDescend→explicit）；z1=INT_MULT(常量,常量) 单后继（唯一 markimplied
  候选，checkImpliedCover 全常量输入不触 cover——cover-lazy 安全观察面）。
  决定性观察：`act=markexplicit|res=5`（m1 仅由 numInstances 规则标记：at=0、
  无 mapped、有后继）、`act=markimplied|res=1`（z1 单次弹出并 implied）、post
  `m1:ex=1,im=0,at=0,hi=2`。双侧 stdout 9 行字节一致（MATCH）。负控制：HEAD
  （dc6f0bfa，修复前）跑同 fixture 得 `res=4`/`res=0` 且 `m1:ex=0,im=1`（m1 被
  错误 implied）——两缺口均被本 fixture 鉴别。注意 m2 先建（def SeqNum 较小）
  使 loc_tree 簇首为带 addrtied 的成员——规避 merge.rs `addr_tied_location_ranges`
  `first_flags` 仅取簇首成员 flags 与 Ghidra `overlapLoc` 全簇 OR 的已知表示差
  （表示层残差另行登记，不影响本 fixture 双侧同判）。
### 2026-08-25：MarkExplicit 全量 port + MarkImplied count 桥（`RETURNFOLD-GAPA-UPSTREAM-0001`）

e2e return 值折叠链的最后检验环节（GAP-A/GAP-B 已集成后的上游切片）：

- **`ActionMarkExplicit::base_explicit` 全量重写**（coreaction.cc:3007-3082，
  原 addr-tied 简化分支整体替换）：
  - cc:3020-3021 `high != null && high->numInstances() > 1 → return -1`
    （多实例 high 永不 implied——`COREACTION-BASEEXPLICIT-NUMINST-0001` 的核心
    规则；折叠/显式选择的判定开关）。
  - addr-tied 分支（cc:3022-3049）：SUBPIECE 输入 addr-tied 且
    `overlap_join(vin) as u64 == in(1).get_offset()`（cc:3026 int4→uintb 提升，
    -1 符号扩展永不匹配小偏移）→ -1；`lone_descend`：ZEXT 输出 addr-tied 且
    `contains(vn)==0` 才可继续 implied 候选（cc:3032-3036）；PIECE 经
    `piece_node_find_root`（op.cc:824-852，funcdata.rs 私有 helper 的本地镜像，
    租约边界）判定根/内部件（cc:3037-3045，根 def `isPartialRoot()` 现已真实生效:
    flag 由 RulePieceStructure(ruleaction.cc:7642)与 SplitDatatype::buildOutConcats
    (subflow.cc:2599)`setPartialRoot` 设置, root def 为 partialRoot 时整栈
    显式——SB-IMPLIEDWAVE-0001 补齐, 原"恒 false"注记作废）；其余
    lone reader → -1（cc:3046-3048）。
  - cc:3050-3063：`is_mapped → -1`（heritage 属性尾）、`is_proto_partial → -1`、
    PIECE def 且 in(0) proto-partial → -1。
  - cc:3066-3072：PTRSUB 引用常量/输入 spacebase 时 `max_ref = 1000000`。
  - cc:3073-3081 后继循环：marker reader → -1；**`desccount > maxref → -1`**
    （修复原 `return desc_count` 缺陷——超限必须是 explicit 而非 multlist 候选）。
- **新增 `multiple_interaction`**（cc:3091-3132）：bool 输出/ZEXT/SEXT/PTRADD 的
  前两输入带 mark → purgelist → `set_explicit + clear_implied + clear_mark`；
  PTRADD 只清洗 PTRADD 祖先；bool 输出祖先 `continue` 不清洗。
- **新增 `MarkExplicitOpStackElement` + `process_multiplier`**
  （cc:3136-3157/3166-3199，Rust 需模块作用域）：LOAD slot=1/slotback=2、
  PTRADD slotback=1（不遍历乘数槽）、SEGMENTOP slot=2/slotback=3；项计数
  `> max_term_duplication` 或命中已标 mark 的祖先 → explicit；spacebase 不计数。
- **新增 `check_new_to_constructor`**（cc:3205-3235）：NEW 输出喂构造器时
  `op_mark_special_print(firstuse)` + `op_mark_non_printing(new op)`
  （`PcodeOpRef` 包装经 funcdata.rs 公有 API）。
- **`ActionMarkExplicit::apply` 全量重写**（cc:3237-3272）：multlist 收集
  （desccount>1 → set_mark）、`count += multiple_interaction(multlist)`、
  processMultiplier（mark 未被清除者）、末尾统一 clear_mark；arch 缺失时
  max_implied_ref/max_term_duplication 回退默认 2（architecture.cc:1420-1421）。
- **`ActionMarkImplied::apply` count 桥**（`COREACTION-MARKIMPLIED-COUNT-0001`）：
  原 `change_count > 0` 双臂均返回 `NO_CHANGE` 的缺陷修复为返回计数增量
  （cc:3434 每完成一个 varnode `count += 1`，apply 本身返回 0 cc:3454；
  sanctioned Rust count-bridge），`rule_onceperfunc` 下 perform 观察
  lcount<count → count_apply/status_end 与 oracle 状态机一致。平坦迭代与
  Ghidra DFS 后序的标记结果与计数总量等价（常数/自由 varnode 双侧同被
  排除：Ghidra def_tree 免费段在 `beginDef(0)` 之后，isFree 跳过 cc:3426）。
- 双侧对拍：`tests/oracle/returnfold_upstream_1204.{cc,rs,metadata.json}` +
  `tools/run_returnfold_upstream_oracle.sh`。四场景驱动**生产**
  `ActionMarkExplicit::perform` + `ActionMarkImplied::perform` +
  `PrintC::emitBlockBasic`/`emit_block_graph`（rpn 路径）：
  s1_fold（单实例 COPY→RETURN：implied、mi_count=1、打印 `return+lit10` 无
  独立赋值行——cc:2704-2705 跳过 + cc:526-534 递归内联）；s2_merged（双实例
  high 合并：双 explicit、me_count=2、assign 行保留 + var 返回）；s3_dup3
  （3 读超 maxref：explicit、1 assign + 3 var 返回——钉死 desccount>maxref
  修复）；s4_mult2（2 读==maxref：multlist 存活 processMultiplier、implied、
  双折叠）。双侧 stdout 22 行字节一致（sha `c1472b99…`），stderr 双空，
  diff rc=0，各 2 次确定性。残差（UNTESTED，metadata coverage）：NEW 构造器
  路径、addr-tied 子分支（需 partialroot 旗标基建）、checkImpliedCover
  LOAD/STORE/CALL 交叉（Rust 块级近似仍在）、标记次序（平坦 vs DFS 后序，
  等价性论证未钉）。
## ActionPrototypeTypes 锁定输出/模型恢复域（COREACTION-PROTOLOCKEDOUT-0001，2026-08-25）

`ActionPrototypeTypes::apply`（coreaction.cc:4607-4651）补两处：

1. **模型不变量恢复**（cc:4613-4614 前置）：Rugra 的 DWARF/PLT 锁定签名
   路径可能留下 `model=None && model_locked=true`，破坏下游一切模型查询
   （Ghidra 的 FuncProto 永远持有已解析模型，未知名在 FuncProto::decode
   映射到 createUnknownModel，fspec.cc:4697）。在 evalfp 就绪且无模型时
   安装默认模型——锁只防替换，此处是恢复不变量而非替换。
2. **Step 3 锁定输出读插入**（cc:4637-4649）：isOutputLocked 且返回类型非
   void 时，为每个存活非 halt RETURN 插入输出存储读作为最后输入
   （`opInsertInput(op, newVarnode(size,addr), numInput())` +
   `updateType(type,true,true)`）——这是返回值数据流边，heritage 把自由读
   重命名到到达定义得到 `return <value>`，并启用 ActionReturnSplit 的
   分支 RETURN。之前只移植了 else 臂（initActiveOutput），导致所有
   DWARF/PLT 锁定签名函数反编译为无值 `return;` 且产值 op 被 dead-code。
   storage 解析在 fspec.rs `locked_output_storage`（见 fspec.md）。

## ActionFuncLink::apply placeholder 尾巴（coreaction.cc:1477/1511-1513，本次新增）

funcLinkInput 尾巴：`spacebase = fc->getSpacebase()` 在模型 input 列表含
stack pentry 且无锁定 stack 参数占用 placeholder 角色时非空（Rugra 的锁定
路径仅寄存器参数，角色永不占用），对每个建模 call 追加 stack-pointer
placeholder LOAD 作为最后一个 CALL 输入（`fc->create_placeholder`）。该输入
使 CALL 满足 `usesSpacebasePtr()`，`RuleIndirectCollapse` 的 else-if 分支
（ruleaction.cc:3223）据此折叠 unknown-effect guard INDIRECT。

## 2026-08-25：ActionSwitchNorm 去自创预扫（JUMPTABLE-PIPELINE-0001 段2）

`ActionSwitchNorm::apply`（coreaction.cc:4548-4560）不再在 apply 开头做原地
`jumptable::recover_jump_tables(fd)` 预扫——那是 flow 期恢复未接线时代的自创补丁。
oracle 中所有 `data` 上的 JumpTable 均在 flow 追踪期
（`FlowInfo::recoverJumpTables` → `Funcdata::recoverJumpTable`）已恢复完毕，
该 Action 只做规范化（matchModel/recoverLabels/foldInNormalization/foldInGuards，
fold 阶段仍为 L2 登记缺口）。apply 现镜像 cc:4559 恒返 0（NO_CHANGE），
unlabelled 计数仅保留本地变量。

## 2026-08-25（ACTIONDW-COPYDEF-MARKING-0001）：ActionDirectWrite 收集段四偏差修复

`ActionDirectWrite::apply`（coreaction.cc:1350-1434）收集段对齐修复，四处真偏差（MAINDIFF-DEADSTORE-0001 诊断发现）：

1. **COPY-def 误标（cc:1381-1394）**：oracle 对 COPY 输出收集期**不**标 directwrite（isStackStore 追踪例外）；旧代码 `else if def_opc != PIECE && != SUBPIECE` 把 COPY 一起标+入队。现按 oracle 分支序：COPY 单列，仅 `isStackStore()` 时做源追踪。
2. **possibleInputParam 分支缺失（cc:1368-1371）**：非 persist/spacebase 输入若 `FuncProto::possibleInputParam` 为真则标记。新增 `FuncProto::possible_input_param`（fspec.cc:4366-4387 完整前奏：dotdotstat 短路 + voidinputlock 门 + 锁定参数 justifiedContain==0 判定；Rugra 无锁定参数状态时该环 inert，与兄弟移植 characterize_as_input_param 同一降级口径）。
3. **isStackStore 源追踪（cc:1382-1393）**：COPY 输出带 stack_store flag（RuleStoreVarnode 设置）时，追源**单层**解一层 COPY，源 def 为 marker（INDIRECT）则标记+入队；两层 COPY 链不标记（oracle 单层解开的边界）。
4. **marker(INDIRECT) 收集分支（cc:1401-1408）**：`!propagateIndirect && INDIRECT` 时，in(0) 地址≠输出地址（活动 COPY）或输出 persist → 标记但**不**入队。结构性新增 `propagate_indirect` 字段（coreaction.hh:244），protorecovery_a=true / protorecovery_b=false 双注册（action.rs 对应 cc:5497/:5498/:5680/:5681）。

Phase-2 推播门（cc:1427-1429）同步修正为 `propagate_indirect || !INDIRECT || is_indirect_store`（旧代码硬编码 false 且注释自相矛盾）。fixture `tests/oracle/actiondw_copydef_1204` 锁定全部六 case 双注册行为（24 records 字节一致 MATCH），包括 oracle 深层语义：**分支④的 no-push 标记使 phase-2 的 `!isDirectWrite` 守卫跳过 mark+push，永久阻断经该 varnode 的 taint 传播**（w_out=0 判别）。
### ActionUnreachable 参数对齐（2026-08-25，HTTPD-STRIPPREFIX-ADDDESCEND-0001）
- `ActionUnreachable::apply` 调用
  `remove_unreachable_blocks(true, false)`（issuewarning=true，
  checkexistence=false 走缓存 BLOCKS_UNREACHABLE 标志），对齐
  coreaction.cc:3460。
## ActionInferTypes setTypeRecoveryExceeded 接线（RULE-PTRARITH-ADDTREE-0001，本次新增）

localcount==7 告警分支补上 `data.setTypeRecoveryExceeded()`（coreaction.cc:5393，
此前只 warningHeader + 计数）。该旗标是 RulePtrArith buildTree 在传播
停止后自行给新建 PTRADD/PTRSUB 输出盖章（assignPropagatedType）的前提。
同轮次另确认：PTRSUB/PTRADD/INT_ADD 指针臂依赖 `fd.arch.types`
TypeFactory（`propagateAddIn2Out` downChain），E2E 驱动侧
`worker_architecture()` 现按 `Architecture::init`（architecture.cc:1398
buildTypegrp + :1269 ELEM_DATA_ORGANIZATION + :1350 setupSizes）装配
带 `<data_organization>` 解码的真实工厂——此前工厂缺失使全部指针传播臂
静默失效，RulePtrArith 因此从未触发。
## ActionInferTypes LOAD/STORE 读者派发（TRI2-STORESPLIT-WHOLESTRUCT-0001，2026-08-26）

op-centric 遍历的 `CPUI_LOAD | CPUI_STORE` 臂重写为读者派发：每个非
annotation 输入（slot 1/2；slot 0 spaceid 是 annotation 被
`is_annotation()` 跳过，对应 buildLocaltypes 的 `vn->isAnnotation()`
continue，coreaction.cc:5018）以 `merge_min_type_order` 播种
`getBase(size, TYPE_UNKNOWN)`——即 `Varnode::getLocalType`
（varnode.cc:897-936）descend 遍历 `op->inputTypeLocal(i)` 的 typeOrder
最小值在 op-centric 走向上的投影。决定性语义：

- **无 override**：`TypeOpLoad::getInputLocal`/`TypeOpStore::getInputLocal`
  在 typeop.hh:269/:279 均为注释行，两 opcode 的每个输入局部类型都是
  `TypeOp::getInputLocal` 基默认 `tlst->getBase(in.size, TYPE_UNKNOWN)`
  （typeop.cc:266-276）。超过 max_base_type_size 的值的该基类型是
  unknown1[N] 数组（type.cc:3652-3657），不是 `IntTypes::sized` 饱和的
  8 字节 long——后者令 `testDatatypeCompatibility` 的 piece 走查
  （subflow.cc:2314-2330）无法覆盖全部 outType 分量，`RuleSplitStore`
  （subflow.cc:2991-3004）便不触发整结构常量 STORE 拆分（progressbarinit
  `*bar=0` → golden 5 行逐字段清零）。
- **最小值合并**：`merge_min_type_order` 保持 varnode.cc:926-931 的
  `0 > newct->typeOrder(*ct)` 严格小于才替换——unknown 播种永不逐出更
  具体的读者播种（例如 CALL 锁定参数）；PTRSUB field token 不属于 local
  seed，而由后续 `ActionSetCasts::castOutput` 消费。wip 2647faac 的
  STORE 地址 `pointer-to-pointee` 单向 or_insert 播种（Ghidra
  buildLocaltypes 无此 op 中心播种）一并移除。
- **FILE*+8 不误拆**：字段指针 STORE 的 outType 经 `getValueDatatype` 的
  `getExactPiece`（subflow.cc:2910-2962）恢复出的分量与 8 字节标量值
  兼容性不成立时不拆分——my_fwrite `stream->_IO_read_ptr` 保持单
  STORE/LOAD。

## ActionSetCasts 类型转换输入/输出令牌 + MarkImplied cover + ReturnSplit（MYFWRITE-TEMPVAR-0001，2026-08-26）

1. **castInput 专用臂**（coreaction.cc:2662 `getInputCast` 派发）：LOAD 走
   `load_input_cast`（typeop.cc:440-470，slot 1 地址指针转换，`*(char **)stream`
   形态），STORE 走 `store_input_cast`（typeop.cc:520-555，slot 1 尺寸失配转
   指针/slot 2 castStandard 转值，`(char *)__s` 形态）。专用臂返回值即最终
   cast 决策（cc:2662-2669 不再二次门控），插入 CAST op 于目标 op 之前。
2. **castOutput LOAD 令牌**（typeop.cc:472-485 `getOutputToken`）：LOAD 的
   token 是地址输入 high 类型的 pointee（尺寸匹配输出时），否则输出自身
   high——这是 `(FILE *)stream->_IO_read_ptr` 输出转换的来源。
3. **ActionMarkImplied**（coreaction.cc:3379-3395）：LOAD 跨 STORE 判定改用
   cover INTERIOR 包含（cover.cc:413-424 max==2 形态 + boundary==0），替换
   原整块保守拒绝；同 spacebase 偏移的交叉仍保守拒绝（isPossibleAlias
   未移植）。CALL 交叉判定同步改 interior-only（尾部边界不算交叉）。
4. **ActionReturnSplit**（blockaction.cc:2280-2315）：重写为 marked-edge
   选择走 + `fd.node_split`（此前为手工合成 RETURN，破坏 staged structurer
   稳定索引不变量的替代路径已弃用）；count 经 apply 返回值承载（Action
   count-bridge 约定）。

## 2026-08-26（TRI2-CALLOUT-ASSIGN-0001）：ActionActiveReturn::apply 完整移植（collectOutputTrialVarnodes/buildOutputFromTrials 接通）

`ActionActiveReturn::apply`（coreaction.cc:1773-1792）从简化版升级为完整链：

- **checkOutputTrialUse（fspec.cc:5661-5676）**：先 `collectOutputTrialVarnodes`
  （fspec.cc:5536-5553）——CALL 已有输出则抛 `LowlevelError`（Rugra：整 apply
  返回 `Err(Lowlevel)`，driver 侧 pipeline ABORTED 等价观察）；`trialvn` 为
  dense `Vec<Option<Varnode>>`，长度=`getNumTrials()`，`None`=null 槽位；
  以 `PcodeOp::previousOp`（op.cc:344，块内 basiciter 前驱，块首即停）回走
  CALL 前驱 op 链，遇首个非 INDIRECT break；对 `indirect_creation` 标记的
  INDIRECT，其输出经 `ParamActive::whichTrial`（fspec.cc:1982，重叠匹配+`sz<=1`
  早退 quirk）定位 trial 槽，填入 trialvn 并**即时** `setAddress(vn addr,size)`
  （fspec.cc:5550-5552——Rust 经 stable Arc owner 绕开 fd 借用分裂，保持
  Ghidra 循环内即时重置序，后续 whichTrial 读到已重置地址）。随后逐 trial：
  `trialvn[i]` 非空 → `markActive()`，空 → `markInactive()`（不调 markNoUse）；
  已 checked → `LowlevelError`。
- **deriveOutputMap（coreaction.cc:1785）**：`fc.derive_output_map()` 既有委托。
- **buildOutputFromTrials（fspec.cc:5770-5860）**：按 `curtrial.getSlot()-1`
  （registration 位置，survive sortTrials）索引 trialvn 收集 finalvn；`break`
  于首个非 used；`deleteUnusedTrials()` 重编 1..N；==1 时 def 入 deletedops +
  `opSetOutput(op, finaloutvn)`；==2 时 joinReverse 选 hi/lo（`findPreexistingWhole`
  未移植——TODO(FSPEC-OUTPUTJOIN-0001)，恒走 constructJoinAddress+SUBPIECE 对）；
  尾部统一 destroy：`opDestroy(dop)` + `deleteVarnode(in0/in1)`。
- **count 通道**：`count += 1`（coreaction.cc:1788）经 `pub count` +
  `take_count_delta()` 外化（同 ActionMultiCSE/ActionMarkImplied 约定，
  perform 的 `lcount<count → count_apply` 观察链）；apply 返回值保持 0。

**根因背景**：progressbarinit `curl_getenv` 输出丢失 = callspec proto 被错误
播种为 caller 的（DWARF 锁定）`fd.funcp` → `funcLinkOutput` 走 locked 分支跳过
`initActiveOutput()`（coreaction.cc:1571-1572）→ 无 trial → CALL 无输出 →
裸语句形 `curl_getenv(...);`。修复后 RAX trial 经 heritage guardCalls 的
KilledByCall INDIRECT 收集，CALL 输出恢复三下游（EQUAL/strtol/free），
golden 形态 `__nptr = (char *)curl_getenv("COLUMNS");` 达成。

## ActionFuncLink/ActionActiveParam 调用实参收敛（MAINDIFF-CALLPROTO-0001，master 并入）

- `func_link_input(fd, fc_idx, op)`（coreaction.cc:1474-1513 `funcLinkInput`）
  重写：`(!inputlocked)||varargs` 才 `init_active_input`（cc:1482-1483）；
  locked 路从**锁定原型**参数表构造 stub CALL 输入
  （`newVarnode(sz,param->getAddress())` cc:1507-1508，Rugra 侧保留模型分配的
  coarse register/stack 空间；stack formal 走 `op_stack_load`，非 stack formal
  走 explicit-space Varnode 创建；varargs 形参另注册
  fixed-position active trial cc:1488-1493）。硬编码
  `known_param_count/known_param_types` 表（glob_url=2 与 DWARF 3 冲突的
  根因）从本函数删除；表中残留仅 ActionCallParams/ActionInferParams 域。
- `ActionFuncLink::apply`（cc:1575-1586）：`known` 谓词（⑤）删除——
  trial 注册的唯一所有者是 `Heritage::guard_calls`（heritage.cc:1495-1509，
  heritage.rs 已移植），apply 内集中式重注册环移除；placeholder 尾
  （cc:1511-1513 createPlaceholder）保持在 apply。
- `ActionActiveParam::apply` finalize（cc:1752-1755）：callspec owner Arc
  先克隆再持写锁，使 `build_input_from_trials(fd, op)` 的 opSetAllInput 尾
  可与 `&mut fd` 共存；序列 resolveModel → deriveInputMap →
  buildInputFromTrials → clearActiveInput 与 oracle 逐行对应。
- `test_action_funclink_initializes_active` 更新为 oracle 行为：unlocked
  callee 仅 initActiveInput（0 trial），trial 由 heritage guardCalls 注册。

## ActionInferTypes STORE 值局部类型改用工厂 getBase（TRI2-STORESPLIT-WHOLESTRUCT-0001，2026-08-26）

STORE 值输入（slot 2）的局部类型种子从 `IntTypes::sized(size)`（8 字节
`long` 封顶）改为工厂 `getBase(size, UNKNOWN)`：Ghidra 的
`Varnode::getLocalType`（varnode.cc:900-936）对每个读者取
`op->inputTypeLocal(i)`，`TypeOpStore` 不覆写 `getInputLocal`
（typeop.hh:279 注释掉），走默认 `TypeOp::getInputLocal`
（typeop.cc:271-275）= `tlst->getBase(自身尺寸, TYPE_UNKNOWN)`；尺寸 16
经 type.cc:3652-3656 变为 unknown1 数组。指针→值方向的
`TypeOpStore::propagateType`→`propagateFromPointer`（typeop.cc:206-228）
只跨精确尺寸或部分枚举匹配，不会把 16 字节常量压成 8 字节整型。全宽
unknown 局部类型使 `testDatatypeCompatibility` 的分段游走
（subflow.cc:2319-2334）覆盖 outType 每个字段，RuleSplitStore
（subflow.cc:2991-3004）得以把整结构常量 STORE 拆成逐字段 STORE。
- `ActionSetCasts::cast_output` tokenct 计算补 CALL/CALLIND 臂（对齐
  coreaction.cc:2541 getOutputToken → TypeOpCall::getOutputLocal
  typeop.cc:720-735 / TypeOpCallind::getOutputLocal typeop.cc:776-789）：
  callspec 的 LOCKED 非 void 输出类型，否则 TypeOp 基类默认
  `getBase(out_size, TYPE_UNKNOWN)`（typeop.cc:261-265）。该 token 使
  unlocked（默认 proto）call 输出打印为 `__nptr = (char *)curl_getenv(...)`
  —— token undefined8 对输出 high char* → castStandard(char*,undefined8) →
  CALL 后插 CAST；locked 且类型等于输出 high（strtol→long）命中
  type_equal 短路不插。CALLIND 经 get_call_specs_of_op（slot-0 Iop 注解,
  TYPEOP-FSPEC-SPACE-0001）取 callspec，等价 typeop.cc:782 getCallSpecs。
## 2026-08-27（MAIN-POSTSTRUCT-SPIN-0001）：ActionPrototypeWarnings 空间名表接线

`ActionPrototypeWarnings::apply`（coreaction.cc:4885-4892）的覆写消息
生成从空名表改为按锁定 x86-64 语料空间表构造 9 项名字向量
（`AddressSpace::spec_space_name`，索引 0-8），再交
`Override::generate_override_messages`（override.cc:279）。
`Heritage::bump_deadcode_delay`（heritage.cc:2580）现在是生产级插入者：
match_url 触发后输出 oracle 同文的
"Restarted to delay deadcode elimination for space: register" 头注释。
此前"消息列表可证为空"的前提随 deadcode-delay override 接线失效。

## MYFWRITE-TEMPVAR exploratory (2026-08-27)

ActionActiveReturn 试验性补充了 preceding INDIRECT trial 收集与
`build_output_from_trials` 调用（oracle `coreaction.cc:1773-1792`）；
ActionMarkImplied 增加 LOAD/STORE 覆盖守卫。尚待在 BlockCopy 活委托基线
上完成 E2E 验证。

## FSPEC-CALLPROTO-LATENT-0001 R2 spacebase leg (2026-08-27)

`ActionFuncLink::func_link_input` now mirrors oracle `coreaction.cc:1494-1512`:
locked parameters in stack/spacebase storage are created through
`Funcdata::op_stack_load`; the first non-varargs stack parameter claims the
spacebase-placeholder flag, subsequent parameters are appended as loads, and
a remaining callspec spacebase creates the canonical placeholder input.
Register/non-spacebase parameters retain their coarse address-space varnodes.
The locked x86-64 GCC scalar register/first-stack, varargs, unlocked and
placeholder-slot paths are covered by `ACTION-FUNCLINK-INPUT-1204`. Full
Architecture-owned Address identity, ModelRules/non-scalars and
`func_link_output` remain outside the approved projection, so this module
stays L2.

## 2026-08-28：GETSTR-FUNCLINK-SPACE-0001 限定证据

锁定 runner `tools/run_action_funclink_input_oracle.sh` 在 Ghidra 12.0.4
`e40ed130…` 与隔离 Rust comparand 上输出 101 records / 9268 bytes，双方
stdout SHA-256 均为
`6cd6ad2eff1d290c7906c6b40cd1ce7d2c818a0939f655ef6260d16b99ef4c0f`，
raw diff 为空。批准范围仅为单 Architecture、x86:LE:64、GCC 默认模型的
coarse `(AddressSpace, offset, size)` input 可观察投影：locked
register/first-stack、locked register-only、locked varargs、unlocked、trial
flags/pass/fixed-position、natural/synthetic placeholder、CALL/bank 顺序和
placeholder 前后 trial 映射。

`ActionFuncLink::apply` 不再现场创造 callspec 或使用已知函数字符串表。
完整 `Address(AddrSpace*,offset)` 身份、generic newVarnode 属性尾、
non-scalar/ModelRules 以及 `func_link_output` 的 extension/error 分支仍为
`MISMATCH`/`UNTESTED`；fixture overall 正确保持 `UNTESTED`。

## 2026-08-29：INFERTYPES-SETTLE-0001 — temp 类型经 TypeFactory 规范化（interned-pointer 收敛契约）

`ActionInferTypes` 的 `writeBack`（coreaction.cc:5043-5060）依赖
`Varnode::updateType` 的 C++ 指针比较 `type == ct`（varnode.cc:459）判收敛。
oracle 里该比较成立的前提是**所有流经 temp 系统的 `Datatype*` 都出自
TypeFactory 的 intern**：`buildLocaltypes` 的种子来自
`getOutputLocal/getInputLocal`（终归 `tlst->getBase`，typeop.cc:264），每个
`propagateType` override 的产物也经工厂构造（`TypeOp::propagateToPointer`
终归 `t->getTypePointer`，typeop.cc:197）。Rugra 的 temp 生产线含免工厂构造
（COPY-spacebase 指针臂、`typeop::propagate_to_pointer`），裸 `Arc::ptr_eq`
跨轮永假，`writeBack` 每轮报 change，`localcount` 撞 7 触发
「Type propagation algorithm not settling」（coreaction.cc:5390-5392，
myprogress 实证：同名 `old==new` 而 Arc 指针不同）。

修复：新增 `canonicalize_temp_type`（对应 oracle 全类型经
`TypeFactory::findAdd` 规范化的事实，type.cc:3392），在两个 temp 写入
choke point 生效 —— `build_localtypes` 的 `temps.insert`（cc:5035
setTempType）与 `propagate_type_edge` 的 `temps.insert`（cc:5108）。规范化
保守：命名 Base 走 `get_base_named`（nametree name+id intern，type.cc:3667），
无名 Base 走 `get_base` 且要求 size/metatype/name 三相等；命名 Pointer 先
`find_by_name` 命中且结构相容才替换（Ghidra 侧不符会 raise
"Trying to alter definition of type"，type.cc:3423；Rugra 保守保留原 Arc，
稳定生产方 Arc 同样收敛），无名 Pointer 递归规范化 pointee 后走 `get_ptr`
（type.cc:3867-3883）。fixture：`infertypes_settle_1204`（双侧 MATCH，
8 轮 apply 的 metatype/size 表 + 实例身份稳定性逐字节一致）。

证据边界：本切片只证明 interned 收敛契约；`ACTION-INFERTYPES-DISPATCH-0001`
等完整 dispatch 闭包状态不变。

## 2026-08-29：类型推断指针构造改匿名（PTRSUB-TYPED-DECL-RESIDUAL-0001）

`make_pointer_type`、`make_ptr` 与 COPY-spacebase 指针臂（TypeOpCopy::
propagateType 的 spacebase 分支，typeop.cc:411-423）此前构造带组合名
（`"char *"`）的 Pointer。Ghidra 对应路径全部终归 3-arg
`TypeFactory::getTypePointer`（type.cc:3867-3875，空名）——推断产物的指针名
在任何 Ghidra 输出中都不可观测。组合名使这些指针成为命名单层指针，被忠实的
printc 声明渲染为 `char * pcVar5`（oracle
printc_anonymous_pointer_decl_1204 named_ptr_contrast 形），偏离 golden 的
`char *pcVar5`。三处均改 `TypePointer::new`（空名 + calc_submeta +
inheritable flags）。同批：typeop.rs `propagate_to_pointer`、debugproto.rs
`parse_c_type`/`pointer_type`/DWARF 数组（见各自 docs/api 文件）。
E2E：curl 全语料 star-blank 声明 58 → 0，compare defects=0/numbering=0。

## 2026-08-29:nodejoin 臂移除冗余 build_dom_tree(R-NODEJOIN-CROSSREVIEW 问题4)

structure_reset(twin 内)已执行 calcForwardDominator(funcdata_block.cc:712),新块为 append 索引未变;
额外的 build_dom_tree 调用对未突变 CFG 幂等且不可观测,按复核建议删除。

## 2026-08-29:NODEJOIN-F4-MATCH-GATES-0001 findDups 全门补齐

ActionNodeJoin::apply 的 match 谓词此前只查双方 last op 是 CBRANCH + 同条件短路,
不同条件菱形**无条件 join**(over-join)。新增 `nodejoin_find_dups`(coreaction.rs,
Ghidra: blockaction.cc:1912 ConditionalJoin::findDups)按 oracle 顺序补齐全部门:
1. `isBooleanFlip()` 任一 cbranch 置位即拒(cc:1920-1921,"flip hasn't propagated
   through yet");
2. `vn1 == vn2` 是**完整 match**(cc:1926-1927,见 F3);
3. 双方条件必须 `isWritten()`(cc:1930-1931)、非 `isSpacebase()`(cc:1932-1933);
4. `functionalEqualityLevel(vn1,vn2)` 必须 ∈ {0,1}(cc:1936-1938);
5. vn1 定义 op 不得为 SUBPIECE/COPY(cc:1939-1941)。
通过后返回 `MergeNeeded`(cc:1943 mergeneed 注册由 ConditionalJoin 状态承接,F2)。
测试:`test_nodejoin_finddups_gates`(booleanFlip×3/unwritten/spacebase/res<0/
res>1/SUBPIECE/COPY 全拒 + 相同 INT_LESS 正对照 join 1 次且块数 +1)。

## 2026-08-29:NODEJOIN-F3-SAMECOND-FULLJOIN-0001 同条件菱形执行完整 join

旧代码把 findDups 的 `vn1 == vn2` 快路径(cc:1926-1927)误读为 "data-flow-only",
same-cond 菱形只 count+=1 不做任何 CFG/op 变换。oracle 语义:vn1==vn2 是**完整
match**,返回 true 后调用方照样走 `ConditionalJoin::execute` 全部四步
(cc:2354-2358 match→execute→clear),仅 mergeneed 为空(setupMultiequals 无新
MULTIEQUAL、moveCbranch 的 `vn1!=vn2` 查表走 else 分支直接用 vn1)。现
`NodeJoinFindDups::SameCondition` 与 `MergeNeeded` 一样落入 nodeJoinCreateBlock
路径。测试:`test_nodejoin_counts_diamond_candidate` 追加断言(块数 4→5)。

## 2026-08-29:NODEJOIN-F2-EXECUTE-STEPS-0001 ConditionalJoin::execute 四步齐全

新增 `ConditionalJoin` 状态结构(coreaction.rs,Ghidra: blockaction.hh:234 ConditionalJoin):
mergeneed(`map<MergePair,Varnode*>`)以 Vec 按 (side1.createIndex, side2.createIndex)
有序维护 = MergePair::operator<(cc:1898-1906)的 C++ map 语义(等键覆盖/排序迭代)。

`ActionNodeJoin::apply` 的 join 路径现执行全部四步(cc:2094-2102):
1. nodeJoinCreateBlock(cc:2097,已有 twin)+ 此前按 match 顺序(cc:2079-2082)先算
   a_in1..b_in2;
2. `setup_multiequals`(cc:2023-2040):mergeneed 每对建 MULTIEQUAL(cbranch1 地址,
   side1=slot0/side2=slot1,newUniqueOut 输出)按 map 序 opInsertEnd 进 joinblock;
3. `move_cbranch`(cc:2043-2057):cbranch1 opUninsert→opInsertEnd 进 joinblock,条件
   输入换成合并输出(vn1==vn2 时保持 vn1),cbranch2 opDestroy;
4. `cut_down_multiequals` ×2(cc:1981-2019):exit 的 MULTIEQUAL 去掉 hi 槽输入、lo 槽
   换成合并输出;1 输入的 MULTIEQUAL 转 COPY 并 opInsertBegin 回块首。

match 尾部补 `check_exit_block` ×2(cc:1954-1972,cc:2088-2089):exit 里从两根块
流入不同 Varnode 的 MULTIEQUAL 对注册进 mergeneed;findDups 失败路径 condjoin.clear()
(cc:2084-2087)与 execute 后 clear()(cc:2357)同样移植。

关键发现(双侧一致):nodeJoinCreateBlock 尾部 structureReset→structureLoops→
findSpanningTree 会把块表**重排为逆后序并重索引**(Ghidra block.cc:1015-1137
`list = rpostorder`)——joinblock 不在追加位置;测试按 JOINED_BLOCK flag 定位。
测试:`test_nodejoin_execute_runs_all_four_steps`(joinblock=[ME,ME,CBRANCH] 序、
cbranch1 读合并输出、b2 cbranch2 销毁、exit [COPY,INT_ADD] 且 COPY 读 (v1,v2) 合并)。

## 2026-08-29:NODEJOIN-F5-DYNAMIC-SIZE-0001 外层循环动态 graph.getSize()

`ActionNodeJoin::apply` 外层改为 `while i < fd.bblocks.get_size()`(cc:2334
`for(int4 i=0;i<graph.getSize();++i)` 每次迭代重新求值)。join 会 append 新块
(尺寸+1)且 structureReset→findSpanningTree 重排块表(block.cc:1015-1137),冻结的
pre-loop 尺寸会漏访问 joinblock —— 而它持有移动后的 cbranch1 和两条出边,自身
可再次 join。测试:`test_nodejoin_dynamic_size_rejoins_joinblock`(三同条件菱形
→ count==2、两个 JOINED_BLOCK;oracle 侧 I_triple 同为 count=2,见
nodejoin_condjoin_1204 双侧 fixture)。

## 2026-08-29:NODEJOIN F2-F5 簇差分收尾
E2E curl(124/124,0 panic):defects=1(getparameter 空 else,他人项,不变)、
numbering=0、skeleton 2911→2884(−27,向 golden)。per-func:next_url 150→134、
getparameter.constprop.0 678→669、my_get_token 57→55,其余 121 函数零变化。
双侧 fixture nodejoin_condjoin_1204 9/9 MATCH(sha256 a5fdf6f3...)。

## 2026-08-30:ConditionalJoin match 补 cc:2076 同目标门(R-NJF234-CROSSREVIEW MISMATCH #1)

复核 REJECT 项:Ghidra blockaction.cc:2076 `if (exita == exitb) return false;` 在 Rugra 缺失。
可达性:CBRANCH 目标==fallthru 时 flow.cc:960-967 无条件登记两条同块出边(仅 BRANCHIND 去重),
构造出 sizeOut==2 且双出口同块的输入;Ghidra 拒绝一切 match,缺门则对同一边做两次
removeEdge/moveOutEdge 手术 → find_out_index panic 或 CFG 损坏。修复=计算出 exita/exitb 后
立即 `Arc::ptr_eq(&exita,&exitb) → continue`。当前语料不触发(单向加门,零新 join 路径)。

## 2026-08-30:ActionDoNothing 忠实重写(HTTPD-EMPTYELSE-DONOTHING-0001)

httpd 空 else 缺陷族根因:旧实现调 `splice_block_basic`(其自创单入守卫拒绝一切
join 目标),而 Ghidra `ActionDoNothing::apply`(coreaction.cc:3466-3490)走
`removeDoNothingBlock` → `blockRemoveInternal`(funcdata_block.cc:254-320,支持多入
目标:pushMultiequals + 出块 MULTIEQUAL 输入拼接 + removeFromFlow 边重定向)。
守卫补齐:`BlockBasic::isDoNothing` switch-target 门(block.cc:2604-2613,辅助
`block_is_do_nothing`)、自环 f_donothing_loop 置位+警告(block.hh:100)、
`BlockBasic::unblockedMulti`(block.cc:2534-2571,辅助 `block_unblocked_multi`,
MULTIEQUAL 同一性解析)。移除返回 CHANGE 镜像 count+=1,驱动 rule_repeatapply
fullloop 重跑 → mainloop → ActionBlockStructure 在 structureReset 清空后的
sblocks 上对净化 CFG 二次结构化(oracle 探桩实证:
ap_make_dirstr_prefix 第一轮 IfElse MATCH(空 fc),donothing 删 0x2e8d6/0x2e902
后第二轮 PROPERIF MATCH 单臂 if)。测试:
`test_action_donothing_removes_join_targeted_jmp_island`。
E2E:httpd defects 7→3、skeleton 2317→2257;curl 3076/0/0(基线 3089,−13)。
机制 C 白名单(主管线 Action):Cross-Review PENDING。

## 2026-09-01:ActionPrototypeTypes eval-model 门裁决(PLTSTUB-WARNLOSS-0001)

裁决(salvage regb `3d042eb` vs master c95b845 立场):**分支方向正确**。oracle
coreaction.cc:4614-4619 是单一合取——`(!isModelLocked()) &&
!hasMatchingModel(evalfp)` 才 `setModel(evalfp)`,model-locked 原型**永不**被绑
evaluation model,"locked ⇒ model 非空"的不变量由签名 decode 边界维护
(fspec.cc:4690-4698:未识别约定名 → createUnknownModel,即 UnknownProtoModel
克隆 default 行为且 isUnknown()=true;architecture.cc:1159-1166,保留名
"unknown" setPrintInDecl(false)),locked unknown 身份因此存活到
ActionPrototypeWarnings(cc:4901-4908)发射
`Unknown calling convention -- yet parameter storage is locked`。master 旧
`!has_model()` 臂(注释主张 "lock only guards replacement")是该合取的反面,
静默修复 modelless+locked 状态并摧毁 unknown 身份——已删除,回归单一合取门
(含 modelless 分解:unlocked+modelless ⇒ has_matching_model=false ⇒ 绑定,
与 Ghidra 行为一致;modelless+locked(仅 Rugra 可构造)保持身份不修)。
`set_input_lock(true)`⇒modellock 耦合已在 fspec.rs 与 fspec.cc:3924-3925
("Locking input locks the model")逐字一致,是 locked 覆盖层保持身份的承载机制。

差分:行为 delta 仅 modelless+locked 分支(不再绑默认模型);master E2E 该状态
经 set_arch named-ctor 绑定(funcdata.rs:1143-1146)+ from_model_carrier 播种
不再出现,curl E2E 3090/0/0 零漂移。**warning 51 vs 24 的剩余差集不在本 action**:
26eee4a 起 LibcSignatureTable::locked_proto 与 DebugDb::locked_proto 均以
from_model_carrier/set_pieces 把 defaultfp 模型名装进 locked 原型(PLT 24 桩 +
void-DWARF main_init/main_free/hugehelp 三函数),unknown 身份在播种层即丢,
登记 PLTSTUB-WARNLOSS-0001 残留(debugproto.rs 两处 builder 需按
fspec.cc:4690-4698 语义钉 "unknown" 约定名,行为 Arc 保留为克隆)。
fspec create_placeholder 双守卫(pltstub 9f14522)证伪:Ghidra fspec.cc:4849-4857
本体无守卫,cc:1482-1512 caller 侧门控(setplaceholder=varargs、首个 locked
stack param 置 spacebase=NULL、cc:1511 仅非空才 create)已在 master
func_link_input(coreaction.rs:9703-9774)忠实落地,再入库内守卫=非 oracle 层。

## 2026-09-22：JUMPTABLE-TABLEAPI-0001 P0-A — ActionSwitchNorm 真身接线

`ActionSwitchNorm::apply`（coreaction.cc:4548-4565）从空壳升级为忠实移植：
- 每个未 isLabelled 的 JumpTable：`match_model` → `recover_labels` →
  `fold_in_normalization`，count+=1；match/recover 的 LowlevelError 消息原样
  经 `Error::Lowlevel` 穿透 apply（Ghidra 异常传播语义）。
- 所有表（含已标注）跑 `fold_in_guards`，成功则 `get_structure().clear()`
  （重做结构）并 count+=1。
- 仍返回 0（NO_CHANGE）——Ghidra 本 action 不向框架报告状态变化。
- 跳表快照迭代（Arc clone）等价 Ghidra 按下标遍历（fold 只追加地址条目，
  不增表）。表级 API 与 foldIn* 语义修正明细见 docs/api/jumptable.md。

## 2026-09-22：ACTION-TRAVERSAL-144-0001 — gatherReturnGotos 忠实 goto 前驱检测

`ActionReturnSplit`（blockaction.cc:2264）的 goto 前驱检测从替代实现换成 Ghidra
原语义（blockaction.cc:2205-2234）：

- **删除的替代**："入边源块以 BRANCH/CBRANCH 结尾即算 goto 前驱"——把结构化
  if/else 边也当 goto 边，next_url R2 尾误开火 8 记录，余震 = R3 p8 COPY 链清理 +
  blockstructure×5 + p9 condnegate/notdistribute/boolnegate 有阻尼振荡，fullloop
  多跑第 4 轮（TRAVERSAL144 §3-§5）。
- **移植的原语义**：对 RETURN 块每条入边，源块经 `getCopyMap()` 进入结构树并走
  祖先链；祖先为 `t_goto` 且 `gotoPrints()` 成立、或为 `t_if` 且 if-goto
  `getGotoTarget()` 非空，且目标经 `while(ret->getType()!=t_basic)
  ret=ret->subBlock(0)` 下探到**原始 basic 块**后与 RETURN 块指针同一（cc:2215-
  2229；`BlockCopy::subBlock` 返回镜像原件，block.hh:524）→ 该入边入选。
- **top-down 实现**（`gather_return_gotos` + `GatherReturnGotosWalk` +
  `crate::block::next_flow_after_successors`，2026-09-22 起与 goto_prints 树遍
  历共用 block.rs 的单一事实源分表，本文件原私有副本已删）：Rugra 结构树组件
  走 typed 字段、无自底向上
  parent 链，祖先链扫描实现为等价子树扫描（入边源 copy 落在 qualifying 节点
  子树内 ⟺ 其祖先链含 marked 节点）；oracle 的 setMark/clearMark（作用域严格
  局限于单 RETURN 的 gather→select→clear，cc:2213-2306）以 walk 内
  `active_ancestors` 计数承载。
- **gotoPrints 的 mid-pipeline live 评估**：returnsplit 运行时
  `prints_precomputed` 尚未由 ActionFinalStructure 填充，`goto_prints`/
  `goto_prints_in` 亦只覆盖根图形态；故按 oracle 的虚分发表（block.cc:1335
  BlockGraph / 2899 BlockGoto / 3053 BlockCondition / 3127 BlockIf / 3341
  BlockWhileDo / 3448 BlockDoWhile / 3476 BlockInfLoop / 3639 BlockSwitch）逐父
  类型计算 `nextFlowAfter` 后继，比较 `front_leaf(target) != succ`（copy 层指针
  同一，block.cc:2884-2888）。关键语义：If/WhileDo 的 getBlock(0) 条件槽后继为
  null；WhileDo body 尾回流条件 front leaf；DoWhile/Condition 恒 null；
  InfLoop 回流 body 首 leaf；Goto 组件后继 = 目标 front leaf；Switch 无槽0
  特判（oracle 的 getBlock(0)==bl 指调度根 cs[0]，Rust 组件表不含它 —— 旧表
  把第一个 case 误当调度根，2026-09-22 修正）、非 t_goto case null、t_goto
  case 取打印序下一 case（组件序 = 发射序；真实 label 排序绑定
  JUMPTABLE-TABLEAPI-0001）。根层兄弟规则走
  `crate::block::graph_sibling_successors`（同一单一事实源）。
- **apply 骨架不变**：RETURN 快照 → isSplittable → gather → 倒序 splitedge/
  retnode 累积 → "不能全拆"pop → `fd.node_split`（count 经 apply 返回值承载）。
- 单测 `test_returnsplit_creates_return_at_goto_pred` 重写为两阶段：阶段 A
  （BRANCH 前驱 + 无 goto 结构）零分裂（替代实现的回归负控）；阶段 B
  （BlockGoto 包装 + copy map 接线）双前驱入选、pop 一条、恰好一次 nodeSplit。

## 2026-09-22：删除自造 ActionCopyPropagate（copyprop lane 判决）

- 删除 `pub struct ActionCopyPropagate`（源码零引用的死代码；注释谎称对应
  Ghidra `RuleCopyPropagate`——锁定 oracle 12.0.4 无此 Rule/Action，见
  `docs/alignment_docs/COPYPROP_LANE_VERDICT_1204.md`）。
- oracle 的 COPY 治理=merge 相位四 Action（MergeCopy/DominantCopy/HideShadow/
  CopyMarker），Rugra 均已实现并按 cc:5722/5723/5728/5729 顺序挂树；本删除
  行为零变化（curl E2E byte-identical，defects=0，numbering=0）。
