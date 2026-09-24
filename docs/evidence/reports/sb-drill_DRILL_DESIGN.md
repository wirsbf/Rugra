# STAGE-BISECT v2：stage 内 per-application modified-op 下钻设计

调查对象：Rugra 工作树 `/home/ls/Rugra`；Ghidra oracle 固定为
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/` 的
`e40ed13014025f82488b1f8f7bca566894ac376b`（12.0.4）。本文只读调查，未修改仓库文件。

## 1. Ghidra 原生机制与确切语义

### 1.1 采集、去重、打印

- `Funcdata::debugModCheck`（`funcdata.cc:1007-1022`）先检查 `op->isModified()`，再检查
  `debugCheckRange(op)`；只有“尚未在本次应用记录过”且命中范围的 op 才设置
  `PcodeOp::modified`、调用 `op->printDebug(before)`，并按**首次触碰顺序**追加到
  `modify_list`/`modify_before`。因此一个应用多次改同一 op 只产生一对 before/after，多个 op 的
  输出顺序不是 optree 顺序，而是第一次触碰顺序。
- `debugModClear`（`funcdata.cc:1024-1032`）清除每个已标记 op 的 modified 位、清空两个缓存并
  关闭 active。当前 oracle 源码搜索没有发现它的调用点；正常 action/rule 路径靠
  `debugModPrint` 完成清理。它是弃用/异常路径的显式“放弃本次输出”API，v2 不应假设它会给出记录。
- `debugModPrint`（`funcdata.cc:1034-1057`）若本轮未激活或没有修改直接返回；否则先关闭
  active，随后在 `modify_list` 非空时执行：
  `opactdbg_breakon |= (opactdbg_count == opactdbg_breakcount)`；输出
  `DEBUG <n>: <actionname>`（`funcdata.cc:1043-1046`），其中 `<n>` 是当前
  `opactdbg_count`，打印后才 `++`，所以首个 native DEBUG 序号为 **0**。每个 op 先输出缓存的
  before 原文，再输出三个空格前缀和当前 `op->printDebug`，然后清除 modified 位
  (`funcdata.cc:1046-1053`)；最后一次性送入 Architecture debug stream
  (`funcdata.cc:1054-1056`)。没有命中范围的修改不会增加计数，也不会产生空 DEBUG 块。
- Action 边界：`Action::perform` 在 `apply(data)` 前调用 `debugActivate`，返回后调用
  `debugModPrint(getName())`（`action.cc:303-322`）；有正向变化且 action breakpoint 未命中后，才
  检查 `debugBreak()`，命中则 `status_actionbreak`、`debugHandleBreak()` 并返回 -1
  (`action.cc:327-340`)。这意味着 DEBUG 块是一次 `apply` 完成后的聚合结果，不是每个内部语句的
  回调。
- pool 内边界：`ActionPool::processOp` 对每条有效 rule 在 `applyOp` 前激活，返回后按 rule
  名打印（`action.cc:829-846`）；若 rule 返回正数，再检查 action breakpoint/debug breakpoint
  (`action.cc:847-858`)。因此 v2 在 `oppool1` 内可直接将每个 DEBUG 块归属于单个 rule application；
  非 pool Action 则归属于该 Action 的一次 apply。

### 1.2 DEBUG 行、seqnum 地址拼写与 dead op

- `PcodeOp::printDebug`（`op.cc:374-384`）严格输出：`<SeqNum>: `，然后若 op dead 或
  parent 为 null 输出 `**`，否则调用 `printRaw`。dead/unattached 标记不是另一个字段，而是
  原文尾部的两个星号。
- SeqNum 的 `operator<<`（`address.cc:32-37`）是
  `sq.pc.printRaw(s); s << ':' << sq.uniq`：即**原始机器地址的 printRaw + 冒号 + uniq/time**，
  不是 Rust `Debug` 结构体格式，也不是带 `0x` 的统一十六进制规范。地址空间 shortcut、字宽、
  wordsize 等由 `Address::printRaw`/空间实现决定。`IopSpace::printRaw` 对非 branch op 使用同一
  SeqNum，对 branch op 使用 `code_<space-shortcut><block-start>`（`op.cc:41-59`）。
- live op 的后半段是 `PcodeOp::printRaw`，其格式由对应 TypeOp；例如二元操作是
  `out = in0 <operator> in1`（`typeop.cc:335-343`），一元是 `out = operator in0`
  (`typeop.cc:357-363`)，函数类操作是 `out = operator(in0,in1,...)` (`typeop.cc:377-388`)。
  Varnode raw 文本使用寄存器名/空间 shortcut、必要的 `:size`、`(i)`、定义 op SeqNum、
  `(free)`（`varnode.cc:705-756`）。因此 DEBUG before/after 应视为完整、带 SSA 身份的
  Ghidra `printDebug` 原文，而不能只保留 opcode。

### 1.3 trace 范围、计数与控制台命令

- `debugSetRange` 追加一个范围并打开 `opactdbg_on`（`funcdata.cc:1059-1072`）。范围匹配
  `debugCheckRange`（`funcdata.cc:1074-1098`）是多个 range 的 OR：若 PC 下界有效，要求
  `pclow <= op->getAddr() <= pchigh`；若 unique 下界不是全 1 sentinel，要求
  `uqlow <= op->getTime() <= uqhigh`。两个维度均为**闭区间**，一个 range 内是 AND；PC 无效时
  完全跳过 PC 过滤；unique 默认全 1 时完全跳过 unique 过滤。
- `trace address` 解析（`ifacedecomp.cc:3464-3491`）：一个地址时 `pclow=pchigh`；第二个
  地址可给上界；没有 unique 参数时两者为全 1；给出则读 `uqlow uqhigh`。`trace enable`
  (`ifacedecomp.cc:3493-3501`) 调 `debugEnable`，它打开 trace 并把 `opactdbg_count` 重置为
  0（`funcdata.hh:600-603`）；disable 只关闭开关，clear 还清空 ranges
  (`ifacedecomp.cc:3503-3522`)。因此 count 的单调性是“单次 debugEnable/Funcdata 生命周期内”
  的单调递增；不是跨函数/跨重置全局计数。
- `trace break <n>` 设置 `opactdbg_breakcount`（`ifacedecomp.cc:3446-3462`），比较发生在
  `debugModPrint` 时且只在有记录的 DEBUG application 上；空修改或未命中 trace 的 application
  不消耗一个 count。`trace list` 会报告每个 range，PC/unique 的打印同样是闭区间说明
  (`funcdata.cc:1100-1118`, `ifacedecomp.cc:3524-3540`)。
- 命令族只在 `OPACTION_DEBUG` 下注册：`debug action`、`trace break/address/enable/disable/
  clear/list`，另有 `break jumptable`（`ifacedecomp.cc:148-157`）；命令类声明同样受宏保护
  (`ifacedecomp.hh:628-644`)。`debug action` 只递归设置 Action/Rule 的 debug flag
  (`ifacedecomp.cc:3431-3444`)，并不替代 `trace enable`。

## 2. OPACTION_DEBUG 构建影响面与 v1.1 兼容性

`types.h:82-97` 规定工程通常只从编译器传 `CPUI_DEBUG`，它会定义
`OPACTION_DEBUG`、`PRETTY_DEBUG`、`TYPEPROP_DEBUG`；Makefile 将 `CPUI_DEBUG` 作为 debug
构建控制开关（`Makefile:104-119`），所以显式 `-DOPACTION_DEBUG` 与 `-DCPUI_DEBUG` 不是完全
同一组副作用。OPACTION_DEBUG 的实际编译影响面如下：

1. **Action/Rule 调试接口与断点**：`action.hh:97-100,160-163,250-253,281-284` 的
   `turnOn/turnOffDebug` 虚函数；`action.cc:62-89,584-608,665-691,936-962` 的递归开关；
   `action.cc:316-322,334-340,839-846,853-858` 的 activate/print/debugBreak 路径。特别是
   `debugBreak` 相关 action.cc:334-340 仅在宏下编译，关闭宏后该可达的中断/续跑路径不存在。
2. **Funcdata 状态与 per-op 钩子**：构造/clear 时的 debug 字段初始化/计数归零
   (`funcdata.cc:74-81,109-111`)，debug API/缓存字段
   (`funcdata.hh:580-612`)，`debugModCheck` 全体实现 (`funcdata.cc:1007-1120`)；所有核心
   op 变换入口在 `funcdata_op.cc:25-33,52-66,70-87,104-141,150-186,203-221,267-317`
   下调用 debugModCheck，Varnode 销毁也在 `funcdata_varnode.cc:269-292` 下钩住。这些入口覆盖
   opcode、output、input、swap、insert/uninsert、destroy、批量 input 等修改。
3. **接口/stream/jumptable**：`Architecture::debugstream` 初始化
   (`architecture.cc:178-180`) 与 `setDebugStream/printDebug` (`architecture.hh:254-256`)；
   console load/restore 绑定 debug stream (`consolemain.cc:103-108,168-171`)，test file 绑定
   (`ifacedecomp.cc:3377-3379`)，`IfaceDecompData::jumptabledebug` 与 followFlow callback
   (`ifacedecomp.hh:54-56`, `ifacedecomp.cc:229-239,424-442`)；jumptable partial action 的
   callback/替代 reset-perform (`funcdata_block.cc:491-519`)。
4. **宏专属旁路调试输出**：`ActionRestructureVarnode` 与输入参数动作在
   `coreaction.cc:2288-2294,4756-4762` 输出 symbol entries；deadcode 在
   `coreaction.cc:4058-4063` 打印 dead ops 后再释放；Scope/MapState debug 字段和 Add Range
   输出在 `database.hh:560-571`, `varmap.hh:187-192`, `varmap.cc:864-879,896-918,1251-1267`。
   这些不是 modified-op 流，但会污染同一 debug stream，harness 必须按 DEBUG 头/格式筛选，不能
   把所有 debugstream 字节当成 v2 record。

因此 v1.1 的“**两侧不带 OPACTION_DEBUG 构建**”承诺不能直接拿来生产 v2 oracle 流：不带宏时
原生 `debugModCheck`、DEBUG stream、trace 命令、debugBreak 都不存在。v1.1 的无宏构建仍应保持，
以确保 stage boundary/snapshot 的比较不受宏引入的运行时分支影响；v2 应使用**单独的、从同一
oracle commit clean rebuild 的 `-DOPACTION_DEBUG` 配置**，并在 META 中记录
`build_flags=OPACTION_DEBUG`、compiler/spec/options。不要把 v2 输出与 v1.1 无宏输出混作同一
MATCH 证据。若要确保宏仅观测不改变语义，v2 harness 仍须使用同一单函数加载协议、同一分析
options，并验证无宏与宏构建最终 C/快照一致；debugBreak 不应启用，trace 仅全函数/范围过滤。

## 3. Rugra 现状：已有等价物与缺失项

### 已有访问器/等价物

- Action 侧已有与 oracle 结构对应的 `Action::perform` 状态机和 `apply_with_state`
  (`src/action.rs:293-360`)，`ActionGroup::apply` 子节点顺序
  (`src/action.rs:896-918,922-938`)，`ActionPool::process_op` 的 per-op/per-rule 顺序和
  opcode 变化重启 (`src/action.rs:1418-1479`)，以及 pool 外层单次 apply
  (`src/action.rs:1493-1518`)。这足以在 driver wrapper 中围绕 `perform/apply_op` 发边界并传递
  full tree path；但当前 `perform` 没有 debug activate/print 钩子（`src/action.rs:323-340`），
  也没有 modified-op 流。
- `Funcdata` 已有主要修改入口：`op_set_opcode` (`src/funcdata.rs:2073-2081`)、输入替换
  (`2101-2193`)、insert input/remove/swap (`2195-2262`)、output (`2264-2293`)、destroy
  (`2295-2337`)、uninsert (`4517-4538`) 以及批量 input/insert helpers。它们是最接近
  Ghidra per-op hook 的统一写入点。
- `PcodeOp` 已保存 `opcode/flags/addlflags/start/parent/output/inrefs`
  (`src/op.rs:291-304`)，有 `is_dead` (`369-372`)、`get_addr/get_seq_num/get_time`
  (`329-343`)；`print_debug` 已有 dead/unattached 的 `**` 分支
  (`src/op.rs:1105-1125`)。`op_addl_flags::MODIFIED` 已定义为 0x4
  (`src/op.rs:58-72`)，可承载 oracle 的去重标记。
- Rust TypeOp trait 已有 `print_raw` API (`src/typeop.rs:135-153`) 及 unary/binary 等实现
  (`src/typeop.rs:292-370`)，Varnode 也有 print_raw (`src/varnode.rs:760-803`)；因此存在
  重建 oracle raw 文本所需的分层材料。ActionPool 还保留 registration order、per-op rule
  索引和 read-only fixture views (`src/action.rs:1188-1207,1231-1260,1286-1299`)，可用于
  path/rule attribution。

### 缺失/不等价项（按 v2 阻塞程度）

1. **SeqNum → addr:uniq 拼写缺失**：当前 `PcodeOp::print_debug` 使用 `format!("{:?}",
   self.start)` (`src/op.rs:1110-1112`)，而 `SeqNum` 只 derive `Debug` (`src/address.rs:370-383`)，
   会得到 Rust struct debug 文本，不是 oracle `address.cc:32-37` 的 `pc.printRaw:uniq`。需新增
   只读格式化器（最好 `SeqNum`/Address 的 Display/raw formatter），不能把 `order` 当 time。
2. **PcodeOp printRaw 未接通**：当前 `print_debug` 自己拼 opcode 与 `v(space,offset)` / input
   (`src/op.rs:1115-1124`)，未调用对应 TypeOp `print_raw`，所以不是 Ghidra `printRaw` 的
   register/shortcut、size、SSA-def 语法。需建立 opcode→TypeOp 的 raw printer，处理 special/
   branch/function/empty slot；已有 `TypeOp::print_raw` 只能算部件，不是现成等价物。
3. **Iop/branch 地址打印残差**：`IopSpace::print_raw` 明确返回 `None`
   (`src/op.rs:259-287`)，注释登记 `SPACE-IOP-PRINTRAW-0001`，而 oracle 对 branch op 有
   `code_<shortcut><block-start>` (`op.cc:41-59`)。要做到真实 before/after MATCH，需补齐
   Address space/shortcut/branch target 语义；不能以 `Address(u64)` 猜格式。
4. **per-op modification hook 缺失**：Rust 入口没有 `debugModCheck` 等价物；`op_set_opcode`
   目前直接 `obank.change_opcode` (`src/funcdata.rs:2073-2081`)，其他 setters 也直接变更。
   推荐在这些 Funcdata 入口内、第一次实际变更之前统一调用 `debug_mod_check(op)`；对递归
   `op_set_output`→`op_unset_output`、`op_destroy`→`destroy_varnode` 等调用链要使用 MODIFIED
   去重，完全镜像 oracle 的“第一次触碰 before”。不能仅在 Rule 返回后比较整池快照：那会丢失
   pool 内 application 粒度、dead 过渡和 first-touch 顺序。
5. **应用钩子与 debug state 缺失**：`Action::perform` 没有 trace range、active、modify list、
   count/break state；`ActionPool::process_op` 没有 rule application 后的 flush。需把 v2 emitter
   放在 driver/fixture wrapper 或受控 debug-only observer seam，优先不改变 production
   `perform()` 语义；如果为纯只读访问需要改 `src/*.rs`，按项目规则只能增加明确
   `RUGRA-GLUE` 访问器并同步文档/证据，不能悄悄改变算法。
6. **full action path 不是现成字符串**：Rust 有递归只读/可变 group/pool view
   (`src/action.rs:164-176,952-955,1165-1168,1536-1539`) 和 name matching，但没有一个在
   perform 调用栈中自动携带 `universal:...:oppool1:Rule` 的 observer/path callback。driver 需
   以显式递归 walker 保持与 oracle tree 一致；不能仅拿 leaf `get_name`（oracle native DEBUG
   也只有 leaf，`tools/stage_bisect_projection.cc:56-60` 已记录此限制）。
7. **debug stream/宏 API 不存在**：Rugra 没有 `Architecture::setDebugStream/printDebug`、
   `debugEnable/SetRange/Break` 等对应对象；v2 可先采用 driver 自己的 sink，但必须复现 oracle
   的 range/count 语义，而不是依赖现有 stderr TAG。已有 `[RUGRA OBSERVE]` FFI 输出
   (`src/ffi.rs:723-730`) 只是 action 改变摘要，不含 op before/after，不能替代。

### 推荐的 Rugra 钩子位置

在每个 Funcdata op mutation API 的“校验/early return 之后、第一次字段或 bank/link 变化之前”调用
`debug_mod_check`；这对应 oracle `funcdata_op.cc` 的宏块（例如 opcode
`funcdata_op.cc:25-33`、input `:104-125`、destroy `:203-222`），并让 nested helper 共享
MODIFIED 标记。每个 Action application 的 wrapper 在 `apply_with_state`/`process_op` 前置
`begin_application(path)`，在返回后 `flush_application(path)`；rule hook 应放在
`src/action.rs:1446-1448` 的 `apply_op` 两侧，普通 Action hook 对应 `src/action.rs:323-326`
两侧。生产主管线不应默认打开；v2 fixture/emitter 通过显式 observer 配置启用。

## 4. v2 格式草案与 before/after 选择

### 4.1 推荐格式

沿用消费端已经接受的 record grammar（`tools/stage_bisect.py:291-309`）：

```text
META side=oracle|rugra oracle_commit=e40ed130... build_flags=OPACTION_DEBUG ...
@BEGIN <application-seq> <full-action-path> ...
<native-debug-seq> <full-action-path> <before-escaped>|<after-escaped>
<native-debug-seq> <full-action-path> <before-escaped>|<after-escaped>
@END <application-seq> <full-action-path> ...
```

建议 record 的 `<seq>` 保留 oracle 的 **native `opactdbg_count`**（首个为 0，只对有 traced
modified-op 的 application 递增），而 `@BEGIN/@END` 的 application 序号继续沿用 v1.1 的
1-based boundary seq。这样既不丢失 Ghidra 的 count 语义，也避免把“无 modified-op 的应用”伪造成
native DEBUG 记录。若当前 v1.1 parser/生产端将 record seq 解释成 boundary seq，则必须在 v2
metadata 明确 `record_seq=native_opactdbg_count`，并在 consumer 中按该定义比较；不要偷偷给
native count 加 1。记录中的 path 使用同一 full path，避免仅靠 leaf name；`before/after` 中
反斜杠和竖线仍按 `stage_bisect.py:58-59` 的规则分别 `\\`、`\|` 转义。

一个 application 改 k 个 traced ops 时输出 k 行，seq 相同，顺序严格为
`modify_list` first-touch order (`funcdata.cc:1046-1053`)。若 application 没有 traced modified
op，只有 v1.1 `@BEGIN/@END`，没有 record。若改动使 op dead，after 保留 `<seqnum>: **`，不要
删除该行；若之后 op 被真正清除而 oracle 在 action 内仍先 debugModPrint，则记录仍以当时 after
为准。

### 4.2 before/after 必须用什么文本

**推荐使用 Ghidra `PcodeOp::printDebug` 原文语义（地址/SeqNum + `printRaw`，dead 为 `**`），
不是 v1.1 的 SNAP op-line。**理由：

1. v2 目标是定位“哪个 application 的哪个 op 从什么状态变成什么状态”；printDebug 保存
   register/space shortcut、size、SSA def SeqNum、operator、dead transition，信息密度足够且正是
   oracle 原生可观测物 (`op.cc:374-384`, `typeop.cc:335-388`, `varnode.cc:741-756`)。
2. v1.1 SNAP op-line 是全池结构快照，字段规范化过且含 `d/out/in`；把它嵌入每个 modified-op
   记录会失去 Ghidra 原文的类型/SSA 可读性、扩大每条记录，也不能表达同一 application 内的
   first-touch 顺序。
3. v1.1 SNAP 仍应保留在 `@END` 后作为阶段级完整状态（若生产端已经实现）；v2 record 是
   增量/因果流，两者职责不同。实现初期可附加 `format=v2-native-printdebug` META，禁止把
   Rust ad-hoc `PcodeOp::print_debug` 当作 MATCH，直到其 raw formatter 完整对齐。

### 4.3 harness 协议建议

- Oracle：独立 clean build `-DOPACTION_DEBUG`，设置 `setDebugStream` 到独立 sink；用
  `debugSetRange` 的无效 PC + all-ones unique 表示全函数（`funcdata.cc:1076-1097`），再
  `debugEnable`。解析 `DEBUG n: leafname` 块；由外层已知 tree walk 给每个 block 补 full path，
  或更可靠地使用 wrapper 在每个 Action/Rule 边界单独包裹 sink，避免同名 Action 的 occurrence
  ambiguity（该风险已在 `tools/stage_bisect_projection.cc:108-123` 记录）。
- Rugra：不要模拟 console `debug action`；在 driver 的显式递归执行 wrapper 里维护 action path、
  native-like count、active/modified map 和 range predicate。生产无宏 v1.1 路径不受影响。
- 两侧都记录 oracle commit、arch/compiler spec、cspec/options、输入 hash、build flags、
  producer hash；宏构建若未记录 `OPACTION_DEBUG`，v2 证据只能判 `NO_ORACLE`。

## 5. 成本、输出量级与风险

### 5.1 粗略量级

仓库当前 `curl_stderr.txt` 显示：`main` 原始 p-code 约 1,388 ops、123 basic blocks
(`curl_stderr.txt:925-929`)，`next_url` 约 249 ops、29 blocks（`:2007-2011`）。每个
modified-op 记录通常约 100–300 字节（SeqNum、operator、每个 varnode 的 raw SSA 文本；长
function/call/PIECE 可能更长）。因此：

- 若只看 first-touch 修改，`next_url` 全函数一个稳定化 round 可能从几十到数百条 records，约
  10–100 KiB；`main` 可能数百到数千条，约 0.1–1 MiB。
- 若 trace 全函数且 action tree 含 repeatapply/restart，池会重复扫全部 ops；同一 op 在不同
  application 会重复记录。对 `main` 这种 1,388-op、123-block 函数，保守按 5–20 次有效
  transformation pass、每次 10–60% ops 被触碰估算约 7,000–16,000 record lines，约 1–8 MiB；
  这是上界式规划数，不是已运行的 oracle 观测值。
- 若把 v1.1 全池 `@SNAP` 也保留，快照体积再按每个 boundary 的 live/dead pool 大小乘以
  1,000–数千字节；建议 v2 调查时只保留首分歧附近的 SNAP 或分离存储，避免日志与 record
  混在同一 stdout。

### 5.2 性能/正确性风险

- 每次 first-touch 需要 range 检查、modified flag、`printDebug` 前缓存；若全函数 trace，
  性能主要成本是字符串化和 stream I/O，不是 range predicate。原生实现将字符串先积到
  `ostringstream` 后一次写 stream (`funcdata.cc:1042-1056`)，Rugra 应同样 buffer，禁止每次
  mutation 直接 flush。
- `printDebug` 读取当前 op/varnodes；若在 Rust 锁模型中持有 write lock 再递归读取输入，容易
  deadlock，应该先释放 mutation write guard 后在 observer 中读快照，或使用同等的短生命周期锁。
- 必须在实际 mutation 之前 capture before；在 `apply_op` 返回后只读当前 op 无法恢复 before，
  也无法识别先改 input 后改 opcode的 first-touch 顺序。
- dead op 仍需保留 `**` after；`opDestroy`/bank destroy 后对象可能不可读，observer 必须在
  `op_destroy` 的逻辑删除/释放前生成 after，且与 Ghidra `debugModPrint` 的时序一致。
- 全函数无过滤会把所有 action/rule 的调试旁路（MapState、symbol entries、type propagation）
  也送入 debug sink；v2 parser 只能接收转换后的标准 records，原始 sink 需另存以便审计。
- 宏构建的 `debugBreak`/console break 状态改变执行停顿点；v2 默认不设置 `trace break`，不
  依赖 breakpoint 继续语义。任何启用 break 的运行必须单独标注，因为计数/`count_tests` 与
  连续运行不再可直接比较。

## 建议落地顺序

1. 先在 oracle 独立 `OPACTION_DEBUG` harness 产一份 raw DEBUG fixture，验证 `DEBUG n`、
   closed range、dead `**`、同 application 同 seq、多 op first-touch 五个断言。
2. 再只做 Rugra debug-only observer：先补 SeqNum/raw formatter 和 `PcodeOp::printDebug`
   等价物，再接 Funcdata mutation hooks，最后接 Action/Rule boundary/path wrapper。
3. v2 consumer 维持现有 record parser 形状，仅新增 META 的 `record_seq`/format 语义和对
   native count 的断言；v1.1 无宏快照路径保持独立。
