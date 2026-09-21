# Stage-Bisect 投影格式规范 v1.1(仓库契约)

> **Oracle 指纹**:Ghidra 12.0.4,commit `e40ed13014025f82488b1f8f7bca566894ac376b`
> (与 AGENTS.md 锁定的源码 oracle 同版),架构 `x86:LE:64:default`。
>
> **用途**:双侧管线 stage 投影(oracle harness / Rugra emitter)的生成与消费契约。
> 投影是单次反编译运行的逐 application 边界 + 完成态快照轨迹,消费端
> `tools/stage_bisect.py`(`--v1` 模式)据此定位双侧首个分歧边界并归因到
> Action 树节点/op 行。
>
> **消费端**:`tools/stage_bisect.py`(权威实现)。Gate 2-E 返修(nested 栈式解析 +
> 身份键前置校验 + per-slot `-` + seq 强连续)见 commit `006db61`
> (baseline `2c9c8b4`);解析决策见下文「实现备注」。
>
> **生产端**:在途 —— oracle harness(Lane A,wt/sb-oracle,
> `tools/stage_bisect_projection.cc` + 真实 curl 单函数驱动)与 Rust emitter
> (Lane C,wt/sb-rust,examples 级)。两侧实现均不得改 `perform()` 树语义
> (`docs/alignment_docs/PIPELINE_STAGES_1204.md` 第 5 节);生产端按规范
> (iii) 如实产出嵌套交错流,勿压扁。
>
> **变更控制**:本规范自 `.slim/deepwork/stage-bisect-e2e.md`「投影格式规范 v1.1」
> 原文转正(Gate 1 attempt2 APPROVE 版,含 M1/M2 补丁与枚举算法钉死)。
> 规范正文锁定,变更需 root + oracle gate。

## 规范正文 v1.1(原文锁定)

**文法契约 = 既有消费端契约的版本化扩展**(stage_bisect.py::parse_line 既有文法:
META/@BEGIN/@END/@CONVERGED/@RESTART + 记录行;升级 parser 与 selftest 由 Lane E 负责,
与生产端同一阶段落地):

```
META side=oracle|rugra oracle_commit=e40ed130... arch=... cspec=...
META analysis_options=<指纹> build_flags=v1-no-OPACTION_DEBUG
META binary_sha256=<...> func_entry=<0x...> func_name=<...> load_mode=single_function_bfd
META producer=<harness-blob-sha 或 rugra-tree-commit> maxrestarts=1 unique_base=<hex>
@RESTART <curstart>                    # Ghidra curstart 原生 0 基字段;首轮不发行
@BEGIN <seq> <tree-path>               # seq=全局单调递增应用序号(1 基);断点停顿不发(纯边界事件不编号)
@END <seq> <tree-path> result=<perform-ret> count=<count-at-completion> tests=<ΔnumTests> apply=<ΔnumApply>
@SNAP <seq> ops <n>                    # 每个 @END 后紧跟一个快照块(v1 扩展;无 OPACTION_DEBUG)
<op-line> x n                          # beginAll/optree 迭代序(两侧同源,已核实)
```

op-line:`<addr-hex>:<time-hex> <OPC_NAME> d=<0|1> out=<vn> in=<vn>[,<vn>...]`
- seq 双段 `addr:time`(address.cc:32-38 正典);d= dead/unattached 位(op.cc:380-381 语义)。
- @SNAP 含 dead 未 destroy 的 op(两侧均 beginAll 语义)。

vn 描述符(**unique 用原始 offset,Gate 1 BLOCKER-1 修正**):
- 常量: `c:<value-hex>:<size>`
- NamedSpace: `n:<spacename>:<offset-hex>:<size>`
- unique: `u:<offset-hex>:<size>` — 原始 offset 直出,**不规范化**。
  两侧 newUnique 序列镜像(varnode.cc:1265-1271 vs src/varnode.rs:3126-3128),
  offset 漂移本身=首个分歧信号(少/多一次 temp 分配→后续全体平移,累积性金丝雀),
  必须归因而非抹除。头部 unique_base 先比基址。relax-unique 仅显式 triage flag
  (对齐 stage_bisect.py --relax-unique 既有哲学:triage aid, not alignment evidence)。

result/count 字段级定义(Gate 1 BLOCKER-4 修正):
- result = 该节点该次应用其 perform() 的返回值(oracle: perform 链路返回;
  断点停顿不发 @BEGIN/@END)。
- count = 该节点 perform 完成那一刻的 Action::count:oracle 经 fixture 访问 hack 读取
  (先例 action_break_pool_1204.cc:561 读 protected curstart 同款模式);
  Rugra 读 ActionState.count,**禁止 take_count_delta()**(它会清空 delta,生命周期不同)。
- tests/apply = getNumTests/getNumApply 差值(action.hh:110-112 公开接口)。
- 声明:断点步进使 count_tests 系统性少于连续运行(action.cc:306-311 恢复 fall-through
  跳过自增)——计数仅在双侧同协议步进下可比,禁止与非步进基线混比。

步进协议(锁定):断点设在树节点 apply 前;步进循环=设断点→perform→返回 -1 时快照上一
节点完成态→续跑。@BEGIN 在节点 apply 开始前发,@END 在完成后发,@SNAP 紧跟 @END。
restart:全树唯一 ActionRestartGroup=universal(max=1);轮次以 curstart(0 基)为准。

事件枚举算法钉死(Gate 1 attempt2 要求,两侧必须同解):
- (i) repeatapply 组内重遍历:每次 apply = 一对 @BEGIN/@END,seq 全局递增不复用;
  同一节点的重复应用各自编号,两侧按同一规则推导。
- (ii) onceperfunc/已完成节点:步进预测"下一节点"必须尊重节点 status 状态机,
  被跳过的节点不发事件、不设断点。
- (iii) 组中途停顿:组级 @BEGIN 已发而组未完成时,先输出内部子节点事件,组级 @END
  在该组恢复续跑完成后才发;嵌套交错序列两侧必须同构。
- op-line 空槽拼写(M1):无输出写 `out=-`;null 输入槽写 `in=-`;逗号分隔保持槽位序。
- @CONVERGED(M2):v1.1 生产端一律不发;每个完成的应用恒发带全属性的 @END;
  @CONVERGED 仅保留为 parser 向后兼容。
- result 读取路径澄清(Gate 2 必查):oracle 侧"perform 链路返回"字面不可观测
  (父组 count += res 吞掉,action.cc:516),实现读法=完成时刻的 count(≡ perform 返回),
  两侧都按 count 读。

构建与边界(Gate 1 第 6 点):v1 双侧均**不带 OPACTION_DEBUG** 构建(消灭 build flag 变量
与 debugBreak 可达性扰动);Rugra emitter 的 src/ 变更仅允许纯只读访问器
(`// RUGRA-GLUE:` 注释);两侧加载契约钉死同一单函数 BFD 契约(同入口/同 context/
同原型与选项注入,Rugra 侧需与 oracle harness 对齐而非沿用全程序 shim 路径时,头部
load_mode 记录差异)。

## 实现备注(消费端解析决策,2026-09-22 Gate 2-E 返修,commit 006db61)

以下决策只约束消费端 `stage_bisect.py --v1` 的解析/比较行为,**不修改上文规范正文**:

- **B-1 栈式嵌套解析**:open-stage 状态由单一 current 帧改为栈。`@BEGIN` 压栈;
  `@END`/`@SNAP` 必须匹配栈顶的 seq+path;`@SNAP` 消费完毕后该 stage 出栈并按
  文件序(完成序)追加进 `stages` 列表。比较器逐下标比较完成序序列——规范 (iii)
  的嵌套交错流(子级先完成)因此合法,两侧同构即可比。附加守卫:栈顶 `@END`
  已发而 `@SNAP` 未发时,只接受该 `@SNAP`(`@SNAP 必须紧跟 @END`);
  `@RESTART`/`@CONVERGED` 仅栈空时合法;EOF 栈非空 = FormatError。
- **B-2 身份键前置校验**:身份键 = `{oracle_commit, arch, cspec, analysis_options,
  build_flags, binary_sha256, func_entry, load_mode, maxrestarts}`。任一不等 →
  独立 kind `V1_META_MISMATCH` + exit 1,且**先于**任何 stage 比较(防止不同
  函数投影互比的静默假 MATCH)。`func_name`/`producer` 保持 warning(两侧本就
  异构);`unique_base` 保持"先比基址"金丝雀 warning,不进身份键
  (Rugra 侧 unique 空间基址与 oracle 不必同值,漂移语义由 op 行金丝雀承担)。
- **R-1 per-slot `-`**:`in=` 逗号列表的元素允许 `-`(null 槽位,槽位序保留,如
  `in=u:1008:8,-,c:1:4`);整列表 `in=-` 仍为 M1 的"无输入"拼写。
- **R-2 seq 强连续**:`@BEGIN` 的 seq 必须等于 last_seq+1(全局 1 基连续),
  缺口或复用 = FormatError(定位生产端枚举 bug)。
- **@CONVERGED 兼容行为**:依规范 M2,v1 模式 parser 保留**顶层** `@CONVERGED`
  兼容接收(计入 converged 列表,不参与比较);出现在未闭合 stage 内 =
  FormatError。"顶层接收但不参与比较"的语义留给 Gate 2-E attempt 2 复核
  (备选:直接拒绝,杜绝又一个静默忽略通道)。
- **selftest**:27 场景全绿 = 13 legacy + 7 原有 v1 + 7 新增(嵌套交错 / per-slot
  null / v1 格式错误路径 battery(bad vn、META 缺 key、seq 缺口与复用、@END
  属性集错、@END 不匹配栈顶、SNAP 前置、EOF 未闭合、杂散 op 行、SNAP 截断、
  @RESTART 位置)/ @CONVERGED 兼容与位置错 / op 行数不等 / d= 位 / 身份键前置
  与 advisory warning)。
