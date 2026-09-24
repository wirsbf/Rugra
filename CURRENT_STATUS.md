# Rugra 当前状态报告

**日期**: 2026-09-25（DFLIP 默认脸快照）
**版本**: 0.1.0
**状态**: 🟡 **核心库持续开发中；锁定 oracle 逐函数差分流水线运转中；全局完成度未证明**

## 2026-09-25 DFLIP 默认脸快照（当前事实源）

**SYMDB 默认转正**（Lane DFLIP，wt/dflip）：httpd 驱动的 action 侧符号 Database 建库+attach+
spacebase scope source 装配与 canon 装配 emitter（EmitPrettyPrint，Oppen 100 列）自本快照起为
**默认行为**（转正判据：功能残差清单清空 + 门控 1315 ≤ 默认 1472，CURB2→DATASYMS→PREGFREE
车道链终报，归档 /dev/shm/rugra-reports/LANE_*_2026-09-25.md）。**默认新脸 == 原门控态逐字节**
（亲测 cmp 恒等）；**逃生门 `RUGRA_SYMDB=0`** 拿回旧 fold-only 脸（1472/0/0，同样逐字节恒等，
旧脸为 opt-out 未删除）；**mirror 路径恒裸**（RUGRA_MIRROR 任何分量在场 → 不建库不 attach 不换
emitter，纯库真值通道）。

| 门禁（fast-release 亲测，@ master a600826e + DFLIP） | 数字 | 说明 |
|---|---|---|
| httpd E2E（默认脸） | **1315 / 0 / 0**（skeleton/defects/numbering，34 函数） | vs `tests/golden/ghidra_httpd_1204.c`；双跑 cmp 恒等；==原 RUGRA_SYMDB=1 门控态逐字节 |
| httpd 逃生门 RUGRA_SYMDB=0 | **1472 / 0 / 0** | ==原默认脸逐字节（fold-only + EmitNoMarkup） |
| httpd mirror（RUGRA_MIRROR=1） | 输出 cmp 恒等亲父 | 裸库真值通道不受转正影响；SYMDB=1 显式开也被 mirror 压制 |
| curl E2E（默认） | **1096 / 0 / 0**（124 函数） | vs `tests/golden/ghidra_curl_1204.c`；curl 驱动未触（curl 的 SYMDB 化另行立项） |
| httpd gcc 审计（默认脸） | 14 OK / 15 FAIL | 旧默认脸 13/16 → +1（DATASYMS readonly 旗标通道随 DB 默认开自动生效） |
| 投影银行（B2 钉板） | **71/71 MATCH** | 全部 curl 语料 + mirror 裸径采集契约 → 不受 emitter/DB 转正影响（亲验） |
| cargo test --lib | 1712 passed / 1 failed | 唯一失败 `test_nonzeromask_pipeline_wiring` 预存（多车道共证） |

**Opt-in 阶梯表（转正后）**：

| 通道 | 环境变量 | 状态 | 语料 |
|---|---|---|---|
| action 侧符号 DB + EmitPrettyPrint | `RUGRA_SYMDB` | **默认开**（`RUGRA_SYMDB=0` opt-out 拿回旧脸） | httpd |
| TYPESEED 提交局部类型种子 | `RUGRA_TYPESEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持 | httpd/curl |
| DWARFSEED 原型种子 | `RUGRA_DWARFSEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持 | curl |
| STRUCTSEED 结构复合种子 | `RUGRA_STRUCTSEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持 | curl |
| mirror 裸库真值 | `RUGRA_MIRROR`/`RUGRA_FLOW_MIRROR` | 在场即恒裸（压制一切 SYMDB 形态），维持 | httpd/curl |

文本级钉板重钉清单（emitter 转正影响面亲查）：**空**——银行 71 项全部 curl 语料且采集命令带
`RUGRA_MIRROR=1`（裸径，转正不改其再生成契约）；`tests/golden/` 为 oracle 侧输出；
`tests/oracle/*.c` 为独立 oracle harness fixture，非驱动产物；tests/ 内无 rugra 侧 httpd 文本钉板。

## 2026-08-28 PTRSUB 正式输出快照

PTRSUB formal working-tree artifact 的 release curl 正式门禁共处理 124/124 个函数，76 个成功反编译，
0 empty/timeout/panic/worker/protocol failure。两次独立 stdout 与当前
`result/curl_cur.c` 三份逐字节一致：SHA-256
`f04dee502dc0131b27b41acb5ec412c0e413515aecf3f29e0e2532b304912a73`，
59995 bytes、2281 行。确定性结论只覆盖 stdout；两次 stderr byte-different（含记录
顺序差异），故不宣称 stderr 一致或全运行确定性。

锁定 Ghidra 12.0.4 golden 的正式 compare 为 skeleton=2820、defects=0、numbering=0；
`progressbarinit` 函数级 skeleton=13，字段清零已恢复为
`*(undefined4 *)&bar->field_0x1c = 0;`。相对 2026-08-27 pre-PTRSUB baseline
（stdout SHA-256 `4404af6da658cc912b84070acb6354073c4649f3b266751e1be6cb81bd1bdc8e`，
skeleton=2822、progressbarinit=15），`diff -U3` 为 12 grouped hunks/7 functions；
`diff -U0` 为 33 atomic hunks、42-/42+。只有 progressbarinit 的 golden skeleton
收敛；其余六个函数的函数级 skeleton 不变，raw 类型/命名 token 有扩散。

gcc 审计仍为 28/123 OK、95 FAIL，诊断类别由 baseline
`{other:1101, undeclared:75, syntax:73}` 变为
`{other:1113, undeclared:79, syntax:73}`。main/getparameter/glob_word/glob_set/
next_url/match_url 出现六个无类型 concrete-pointer 声明，已登记
`PTRSUB-TYPED-DECL-RESIDUAL-0001`；`glob_set` 新增 cast churn 另登记
`PTRSUB-SWITCH-CAST-RESIDUAL-0001`。fixture overall 仍为 MISMATCH，production
closure 不得据 skeleton 净减 2 升级。完整残差与依赖见 `docs/TODO_BOARD.md` 顶部。

`cargo test --lib -- --test-threads=1` 为 1618 passed / 17 failed / 5 ignored；
full suite 仍 FAIL，但 17 个失败名与 2026-08-27 归档基线完全相同，本候选新增失败=0。
首个为既有 funcdata CONTINUE 断言，其后 16 个为锁中毒后的 `PoisonError` 级联。

## 关键指标增量（2026-08-25 第二批，master `ef26eb24`，89 项集成）

> 第一批增量见下节。本批为同日后续 wave（触发词：三函数收敛 + 函数体差距分诊）。

| 维度 | 第一批末 | 本批末 | 说明 |
|---|---|---|---|
| curl 差分 skeleton | 2012（口径含 6 timeout 隐藏） | **2849**（124 函数全输出、main 恢复后真差异显形；超时/panic 清零使隐藏 diff 显形，同口径逐函数净账 21 改善−380 vs 2 回归+6） | goto 0→22、裸条件 50→0、extern DAT 69→0、->literal 175→0、in_register 裸名≈清零、空 if 体 7→6 |
| defects / numbering | 0 / 0 | **0 / 0** | numbering 由 isComplex 集成顺带归零（match_url 合法 \|\| 折叠恢复） |
| 三函数严格字节 | 0/3 | **0/3**（结构大幅收敛） | my_fwrite 守卫+fwrite+return 恢复（剩 21 行 TEMPVAR 在途）；progressbarinit `__nptr` 达成 golden 同名（13 函数获 DWARF 推荐命名）；hugehelp 六 puts 结构就绪等 CPTR |
| main 状态 | 1 TIMEOUT | **0 TIMEOUT（30s 对齐 oracle）**，894 行 diff 已分诊 6 桶（结构化 373/命名 171/全局 162/常量字符串 181/死存储 105/调用原型 52） | argc 原型 `int main(int argc,char **argv)` 逐字节=golden |
| httpd 语料 | 未测 | 首回归跑：timeout 全消、21 函数净 −53；暴露 2 P0 panic（已钉死引入 commit，修复在途）+ goto 三缺陷家族（curl 零覆盖路径） | 报告 /tmp/rugra-reports/HTTPD-GATE-c1e3733d.md |
| 复核闭环 | — | 本批 5 复核：4 APPROVE（含 mutation 实证）+1 REJECT（回走双步，C++ 复刻实证）→ 返修中 | 机制 C 运转正常 |

## 关键指标增量（2026-08-25 第一批，W-2026-08-24-TRIFUNC-GAP wave 进行中）

> 本节为 wave 期间增量快照；上节 2026-08-21 数据为 wave 前基线。任务明细见 `docs/TODO_BOARD.md` 活跃 wave 段，
> 过程证据链见 `docs/alignment_docs/WAVE_STATUS_2026-08-25*.md` 与 `docs/alignment_audit/REVIEW_*` 系列。

| 维度 | wave 前（f7b3c31） | 当前 | 说明 |
|---|---|---|---|
| curl 差分 skeleton | 2409 | **2012**（noreturn 全链后干净树测量；master 另有 merge-panic 三函数修复在途，合测后为正式值） | flow 尾调用修复 −32 → varmap 窗口交互 +28 → noreturn 全链 −393 |
| defects / numbering | 2 / 1 | **0 / 0**（同上测量） | file2string 全 MATCH；helpf 缺陷清除 |
| wave 集成数 | — | **33 项实现 + 8 项独立复核批准 + 2 项 REJECT→返修→APPROVE 闭环** | 全部带双侧 oracle fixture 或差分门禁 |
| 逐字节全 MATCH 函数 | 4/75 真实内部 | file2string.part.0 新增（143→0） | my_get_line 160→83、glob_word 144→81、helpf 137→86 持续收敛 |
| merge-panic 回归 | 0 | 3 函数（my_get_line/helpf/file2string）worker panic @merge.rs:916 | 修复中（A36）；1958/0/1 的中间测量因此无效 |
| cargo test --lib | 可用 | 可用（E0423 已修 `b55ef7f`） | 3 个预存失败在板（comment/funcdata×2） |

**wave 机制运行数据**：≥10 并发子 Agent 持续维持（峰值 14）；独立复核 13 轮（R1-R13，含 2 次 REJECT 均抓到 fixture 抓不住的真缺陷）；
三函数根因链全部进入实现/集成态（hugehelp 四环节、progressbarinit 双方案、my_fwrite exact-piece→SPLITDATATYPE）。

## 关键指标（2026-08-21，HEAD `5dc86ba`）

| 指标 | 当前 | 核实方式 |
|---|---|---|
| 单元测试 (`cargo test --lib --locked --offline`) | **1453 通过 / 2 失败 / 3 ignored** | 从 HEAD + staged datatype 补丁隔离构建；仅余 `funcdata::test_type_propagation` 与 `test_infer_params_and_return_type`，均绑定 `ACTIONTYPEINFER-VTYPE-0001` 依赖链 |
| curl E2E | **124/124 处理，75 反编译 / 1 timeout / 0 panic / 48 import stubs** | 从 HEAD + datatype 补丁隔离 release 重生成，stdout/stderr 分离 |
| 12.0.4 差分 | **skeleton 2762 / defects 0 / numbering 0 / Matched 123/124** | 对本轮重生成输出与 canonical `tests/golden/ghidra_curl_1204.c` 复核 |
| xunknown/xVar | **0**（TYPE-WIRING 双轨消除） | grep 归零 |
| FUN_ 未解析调用 | **5**（起点 64；CALLSPEC 接线） | grep |
| 逐字节一致函数 | **52/123：48 个外部桩 + 4/75 个真实内部函数** | 2026-08-24 词法函数边界原始字节复核；详见下节，旧值 50/122 已废止 |
| gcc 审计 | **107 OK / 16 FAIL**（畸形 cast 1262→0、`+ 0 -` 3→0 后余量=varmap/typedef 域） | audit_syntax |
| 确定性 | 20×全语料 + 20×compare main 字节一致 | check_determinism.py |
| oracle fixture | **registry 88 个** | `jq '.fixtures | length' tests/oracle/fixture_registry.json` |

> 全局完成度仍未证明：逐函数账本分母与旧报告尚未完成生成器重建核对，且账本仍含 `MISSING/MISMATCH/NO_ORACLE/UNTESTED`。本页的局部 MATCH 不代表模块或项目 L3。

### 2026-08-24 严格函数字节审计

对 2026-08-24 当时捕获的 `result/curl_cur.c`（SHA-256 `41aec0b7ddd8cdaddb0571f88320d811ee9530d447ace631e0d96afac61a812e`）与锁定 12.0.4 golden（SHA-256 `aca3798881fddc2ce541c3e731b88f9fcf4736451db98fdd9247366f78b6097f`）按地址配对，严格比较从函数签名首字节到词法匹配闭合 `}` 的原始字节。函数内部的空格、空行与换行全部保留；函数外 header、warning、分隔空行和 summary 不计入函数体：

- 该快照输出 123 个函数块，golden 124 个；可比较 123 个，全部按 `Ghidra地址 - 0x100000` 命中，golden 的 `main` 在该快照输出无对应成功函数体。
- 严格函数体逐字节相同为 **52/123**：48/48 个 synthetic/import bad-instruction 桩，以及 **4/75 个真实内部函数**。
- 四个真实内部函数为 `GetStr`、`main_free`、`__libc_csu_fini`、`_fini`；若以 golden 的全部内部函数为分母，则是 4/76，缺失的 `main` 记 `MISSING`。
- `tools/audit_syntax.py` 的独立函数解析器复现相同的 52 项结果。旧的 47/123、内部 0/75 是错误的分段口径：它把函数外空行/warning 混入四个内部函数，并让最后一个外部桩吞入 summary。

因此在该 2026-08-24 快照中，对“有多少真实函数体逐字节完全一致”的答案是 **4**。这仍只是当时的最终 C 文本证据，不自动把对应全算法调用闭包提升为 B2 `MATCH` 或模块 L3。

### 2026-08-20 当前 wave 落地

- 基线失败从 5 项收敛到 2 项：Comment 地址/XML content codec（`20cc7b2`）、DynamicHash op-tree 顺序（`a29f5b7`）、RuleAddUnsigned 类型前提测试（`c97ac93`）均有锁定 12.0.4 双侧 fixture。
- 高扇出地基已原子化：RangeMap common refinement 与稳定 cursor（`8ec6bee`，43/43 MATCH、独立复核 APPROVE）、TypeFactory ordered local cache（`a4a2fe9`，99-record 投影 MATCH、整体 MISMATCH）、typed UserOp metadata（`128a127`，61-record 投影 MATCH）、typed CPoolRecord（`973efbf`，16/16 覆盖投影 MATCH、整体 MISMATCH）。
- Merge 的固定名称启发式已替换为 canonical no-char 类型身份（`e15b91b`，29/29 覆盖投影 MATCH、整体 MISMATCH，窄面独立复核 APPROVE）。
- 独立复核阻止了多次虚假收口：pipeline tree、旧 varmap 查询实现和 datatype type-order R1/R2 均为 REJECT；前两项保持未提交，datatype R3 已以 `5fb36f0` 落地（78 records：72 投影 MATCH、6 TypeFactory MISMATCH，scoped Cross-Review APPROVE）。
- 剩余两项全量测试失败不能用 `None`/fallback 快修；正确依赖链为 `DATATYPE-TYPEORDER → TYPEOP-LOCALTYPE-DISPATCH → VARNODE-LOCALTYPE-RESOLUTION → ACTION-INFERTYPES-DISPATCH`。

### 终局指标（2026-08-17 收官）：warning 51/51=golden、`=` ( 畸形 1262→0、INDIRECT UnknownEffect −73%、stderr 风暴 48→0、11+ 轮机制 C（4 轮 REJECT 拦截真实分叉/误引）

### 本 session（2026-08-15~17）落地摘要

**Heritage 全链收官**（全部机制 C APPROVE，历经 1-4 轮复核）：
OWNERSHIP(0618b1c) → CALLGUARD(126b56f) → ADT-RENAME(c96f699，含确定性根修 df HashSet) → DRIVER-SWITCH(c309130，canonical 单 pass 生产切换)。

**typed-decl 链收官**：①LINKSYMBOL(0e4c6f4，local_ 106→0) → ②SCOPE-SYNC(3888124，8/8 MATCH + 补复核 APPROVE) → ③PRINTC-SYMBOL-DECL(df0da85，numbering 259→0)。

**地基与外围**：ADDRESS 空间句柄(ff3f8c8) / SPACE registry(fb9458e) / undefinedN 双 flavor(b96e6f9) / TYPE-WIRING(38af1fd，xunknown/xVar 归零) / CALLSPEC(a4dcfdf，FUN_ 64→5) / EXTERNAL-STUB(83360f48→0) / SUBCANCEL 死锁修(03ec065，7 函数解锁) / INPLACE-MUTATION(3cee3ac) / merge 持久化+门(7046998/543db17) / 五项 merge 门 / copy_shadow / FinalStructure / get_inheritable coretype 修正 / 六 fixture 重 pin 全绿。

**工具链**：12.0.4 真 headless golden(0c912e9) / 确定性双跑 CI 门禁 / audit_syntax 修复 / oracle registry 治理 / reducer schema-2 / registry ID scheme-2 迁移（STALE/REKEY/UNMAPPABLE 归零）。

### 2026-08-15 wave 落地摘要（20 提交，全部带真实 oracle 门禁或独立复核）

- **ee29a32** Cover 自锁根因修复（root-identity 快照重建，8/8 MATCH + Cross-Review APPROVE）；E2E parseconfig TIMEOUT→数秒
- **91b4774** makeFree 身份删除（Ghidra 存储迭代器语义，4/4 MATCH；单测 11→6 失败）
- **18f3ab4** `BlockGraph::findSpanningTree` RPO index 完整移植（8/8 MATCH）
- **d124392** RangeProperties marshal 重 pin（11/11 MATCH，真实 TreeDecoder 未注册名→159）
- **192e894** varmap 权威命名（共享 base 计数器 + SymbolNameTree，6/6 MATCH + Cross-Review APPROVE）
- **121c429** Subflow outvn 收敛 + 死锁 + 2 语义偏差（15/15 MATCH；my_get_token panic 消除）
- **e034f80** SLEIGH const 空间相对分支→内部 p-code 边（81 ops/33 relatives/34 blocks/49 edges MATCH）
- **763d564** totalReplace 单程 + opUnsetInput 幂等（glob_range 120s→1.1s，WARN 1454→0，E2E 24/24）
- **138dd24** post-cleanup 动作顺序对齐 coreaction.cc:5714-5738（28/29 一致 + Cross-Review APPROVE）
- **0d38e6e** ActionReturnRecovery 生命周期（mainloop ABA 消除，match_url 120s→102ms；B2 记 UNTESTED）
- **0618b1c** Heritage 显式所有权边界（3/3 MATCH + Cross-Review APPROVE；未切生产 Action）
- **2dfc91b** 函数 ID scheme 2 + 账本重生产物
- 工具链：07efbff reducer schema-2、d099737 oracle cache 三重加固

### 后继队列（均已登记 TODO_BOARD）

高扇出地基：`BLOCK-INDEX-WIRE-0001`（接线公共 RPO）/ `BLKACT-FINALSTRUCT-COUNT-0001`（删一行即 28/29→MATCH）/ `MERGE-PERSISTENT-STATE-0001` / `HERITAGE-CALLGUARD+ADT-RENAME+DRIVER-SWITCH`（生产切换链）/ `ORACLE-REGISTRY-0001`（registry 45 RG-F + 7 GH12-F 迁移，依赖已满足）/ `UPSTREAM-OUTVN-DEADWIRE-0001`（340 free-varnode WARN 归因）/ `COVER-TWOPIECE-RESIDUAL-0001` / `BASE-EXPLICIT-GAPS-0001` 等，详见看板。

### 2026-08 工具链与验证地基（摘要）

锁定 oracle 差分流水线已工业化：逐函数账本（scheme 2 稳定 ID）、内容寻址 oracle cache（环境/TOCTOU/闭包三重加固）、edit/commit/wave/nightly 四级门禁、changed-function→fixture 选择器、stage 快照首差异定位、deterministic reducer（schema-2 签名合同）、不可变 fd runner（空环境重建锁定 Ghidra + 校验和隔离 vendor 的 Rust snapshot）。详见 `docs/TODO_BOARD.md` DONE 行。

---

## 以下为历史记录（2026-06/07 口径与 2026-08-15 早间数据，部分数值已被上方覆盖）

## 关键指标（2026-07-02 重新核实）

| 指标 | 当前 | 核实方式 |
|---|---|---|
| 单元测试 (`cargo test --lib`) | **736/736 通过** | 2026-06-28 实跑 |
| curl gcc 审计 | **24/24 OK 0 FAIL** | `python tools/audit_syntax.py result/curl_cur.c` |
| httpd gcc 审计 | **29/29 OK 0 FAIL** | 同上 |
| curl 结构缺陷 | **17/24 函数有缺陷**（空 else / 寄存器泄漏 / 调用丢失） | `python tools/compare_ghidra.py --summary-only` |
| curl 变量编号问题 | **0 个**（checker 修复后；详见下方 2026-07-27 备注） | 同上 |
| goto | **0**（curl + httpd） | 实测 |
| uVar 碎片 | **0** | 实测 |

> ⚠️ **旧 while/if 计数 KPI 已废弃**（2026-07-02）。计数相同 ≠ 结构对齐（for↔while 等价变换），且检测不到真实缺陷。详见 `tools/compare_ghidra.py`（重写为结构骨架 diff + 编号连续性检查）和 AGENTS.md 铁律 11。

### 2026-07-27 numbering checker 修复（numbering 749 → 0）

`tools/compare_ghidra.py` 的 `check_numbering_continuity` 旧实现用 `VARDECL_RE` 扫整个函数体，把每一次变量**使用**当成**声明**计数（`return pcVar1;` / `if (bVar5)` / `bVar3 = ...` 全被计入）。这导致 fc6fd1f 引入类型前缀命名后，numbering 从 3 暴涨到 749——而其中**全部都是误报**：连 Ghidra 自己的正确黄金输出（`tests/golden/ghidra_curl.c`）也被同一 checker 报 995 个问题。

修复：改为只统计**声明行**（`^[ \t]+<C 类型>...<Var 名>(;|=)`，要求 Var 名前是真正的 C 类型关键字而非 `return`/语句关键字），并用**共享计数器不变量**替换被声明字母序干扰的 per-prefix 文本序单调性检查——直接抓 181538f 类 per-prefix 计数器 bug（max(num) << 声明总数）。修复后 Rugra 与 Ghidra 黄金输出 numbering 均为 0。详见 `tools/compare_ghidra.py` 注释。


### 2026-06-28 双重突破（历史记录，数值已被后续覆盖）

**突破 1：CFG 基本块划分修复**（commit 2bcfcde）
- 根因：`build_blocks_from_ops` 不在跳转目标地址处分裂块，导致回边丢失
- 修复：忠实移植 Ghidra 块划分（terminator + 跳转目标分裂点）
- 效果：循环回边检测恢复（旧计数显示 curl 循环数大幅提升，但该计数已不作为 KPI）

**突破 2：identify_internal RwLock 死锁修复**（commit e581dbc）
- 根因：identify_internal 持有 write guard 时对自环边的 point 调 read，write+read 同一 RwLock 死锁
- 修复：4 处 `e.point.read().unwrap()` → `try_read()`，失败跳过
- 影响：httpd 从"卡在第 8 个函数"变成"完成全部 29 函数"

**类型修复链**（commits 7a9b359/89bf0d4/1e67ae6/73f2581/3aa2fe7）：reconcile int-pointer 减法/除法 + 死循环修复 + 指针类型匹配 cast + discovery pass 不可达块遍历 → curl 审计 24/24。

## 已接入且实际生效的模块（curl/httpd 验证）

| 模块 | 效果 |
|---|---|
| **ActionConditionalExe** | 接入主管线，curl 无匹配模式正确返回 NO_CHANGE |
| **ActionPool (44 Rule)** | 接入 ActionSimplify 之后，Rule 真实触发（main 28 pass_changes） |
| **ActionRestructureVarnode** | 接入 DeadCode 后，构建 scope + sync_varnodes_with_symbols |
| **RuleOrPredicate** | 接入 ActionSimplify，扫描 INT_OR/INT_XOR |
| **LoopBody pipeline** | parseconfig 检测嵌套循环 (depths=1,0)；orderLoopBodies 全 pipeline 运行 |
| **TraceDAG + goto cascade** | 176 条 goto 候选边处理；selectGoto + emitLikelyEdges 集成 |
| **uVar 内联 (printc)** | emit_inline_expr COPY 内联，uVar 149→0 |
| **spacebase 解析** | resolve_rsp_offset_via_bank，helpf 栈符号 5→9 |
| **switch cast (long)** | switch 表达式 (long) cast 保证整数性 |

## 已实现但需 example 层接线才能触发的模块

| 模块 | 状态 | 未触发原因 |
|---|---|---|
| **ActionFuncLink** | ✅ apply 完整+接入管线 | curl_decompile.rs 不创建 FuncCallSpecs |
| **ActionActiveParam** | ✅ ProtoModel.fillinMap 驱动 | 同上 |
| **ActionActiveReturn** | ✅ output trial recovery | 同上 |
| **ActionDeindirect** | ✅ 常量目标解析 | 同上 |
| **ActionReturnRecovery** | ✅ RETURN 扫描 | 需 FuncProto active_output |

**修复方法**：在 curl_decompile.rs 的 lift 阶段为每个 CALL/CALLIND 创建 FuncCallSpecs。

## 已实现但未接入主管线的模块

| 模块 | 状态 | 未接入原因 |
|---|---|---|
| **ActionUnreachable** | ✅ apply 完整 + remove_unreachable_blocks | 接入导致回归 (curl 24→11) |
| **ActionDoNothing** | ✅ apply 完整 + splice_block_basic | 同上（staged structurer 依赖被删块） |
| **ActionRedundBranch** | ✅ apply 完整 (case1 splice + case2 remove_branch) | 同上 |
| **ActionDeterminedBranch** | ✅ apply 完整 | 同上 |

**修复方法**：需 staged→collapseInternal 架构迁移（G4 可选优化）。

## 本会话移植的核心 Ghidra 算法（按源文件）

### ✅ condexe.cc — 全部移植（L3）
- ConditionalExecution 18 方法（testIBlock/findInitPre/verifySameCondition/doReplacement/pullbackOp/execute 全部）
- RuleOrPredicate 7 方法（MultiPredicate 4 + getOpList/checkSingle/applyOp）
- BooleanMatch/BooleanExpressionMatch（expression.cc:57-232）
- 底层原语：replace_edges_thru / remove_from_flow_split / find_common_block / compare_order

### ✅ blockaction.cc — LoopBody + selectGoto（L2 核心完成）
- LoopBody 完整类（find_base/extend/find_exit/order_tails/label_exit_edges/label_containments/merge_identical_heads/emit_likely_edges）
- orderLoopBodies pipeline
- apply_loop_exit_marks（setExitMarks）
- TraceDAG isLoopDAGOut 集成
- FlowBlock 标记原语（mark/visit_count/loop_exit/goto_in/out）
- edge_flags 新增 F_LOOP_EXIT_EDGE/F_BACK_EDGE/F_IRREDUCIBLE_EDGE

### ✅ emulate.cc — execute() 主循环（L2 核心完成）
- execute_current_op（executeCurrentOp, emulate.cc:143-216 全 opcode dispatch）
- execute() 主循环
- get_value/set_value（值解析，非仅常量）
- execute_unary/binary/load/store

### 🔧 coreaction.cc — 8+ Action apply()（L2 进展）
- ActionDeindirect（常量目标解析 + COPY 链追踪）
- ActionFuncLink/FuncLinkOutOnly（funcLinkInput/funcLinkOutput）
- ActionActiveParam（ProtoModel.fillinMap 驱动）
- ActionActiveReturn（output trial recovery）
- ActionReturnRecovery（RETURN 扫描）
- ActionRestructureVarnode（sync_varnodes_with_symbols）
- ActionUnreachable/DoNothing/RedundBranch/DeterminedBranch（apply 完整，未接入）
- ActionPool Rule 调度器（44 Rule 接入主管线）

### 🔧 fspec.cc — 参数恢复完整闭环（L2 进展）
- ParamTrial（30+ 方法，fspec.hh:210-273）
- ParamActive（15+ 方法，fspec.hh:285-380）
- ProtoModel/ParamEntry（type_system/protomodel.rs）
- checkInputTrialUse（ProtoModel.possible_input_param 驱动）
- deriveInputMap（ProtoModel.fillin_input_map）
- buildInputFromTrials（参数恢复最终输出）
- FuncCallSpecs: active_input/active_output/proto_model 字段

### 🔧 subflow.cc — SubvariableFlow 完整三段式（L2 进展）
- doesOrSet/doesAndClear（mask 分析原语）
- doTrace（worklist 驱动入口）
- traceForward（~286行，全 opcode 模式匹配）
- traceBackward（~196行，定义 op 反向追踪）
- doReplacement（替换执行引擎）

### 🔧 constseq.cc — 核心算法（L2 进展）
- interfereBetween（干扰检测）
- checkInterference（序列收集）
- RuleStringCopy applyOp（字符串序列检测）

### 🔧 userop.cc — 专用子类（L2 进展）
- DatatypeUserOp/VolatileReadOp/VolatileWriteOp
- SegmentOp/JumpAssistOp/InternalStringOp

### 🔧 unify.cc — 约束系统（L2 进展）
- 16 个约束类型（OpCode/OpEqual/VarnodeEqual/OpOutput/OpInput 等）
- evaluate/evaluate_mut（只读/动作约束评估）

### 📋 dynamic.cc — DynamicHash（L1 从零创建）
- ToOpEdge + translate_opcode + DynamicHash
- calc_hash_vn/calc_hash_op（CRC 哈希计算）
- 5 个单元测试

### 🔧 printc.cc — uVar 消除 + scope声明（L2 进展）
- emit_inline_expr COPY 内联（uVar 149→0）
- switch (long) cast
- scope 符号保守声明
- used_scope_symbols RefCell

### 🔧 varmap.cc — spacebase 解析（L2 进展）
- resolve_rsp_offset_via_bank（只读 def 桥接）
- ActionRestructureVarnode 接入

### 🔧 funcdata.rs — 新增原语
- remove_unreachable_blocks / splice_block_basic
- sync_varnodes_with_symbols
- structure_reset

### 🔧 block.rs — 新增原语
- replace_edges_thru / half_delete_in/out_edge
- remove_block_arc / remove_edge_blocks / find_common_block
- FlowBlock: set_mark/clear_mark/visit_count/set_loop_exit/is_goto_in/out

## 剩余工作

### P0（影响输出质量/接入）
- curl_decompile.rs 为 CALL/CALLIND 创建 FuncCallSpecs → 解锁 FuncLink/ActiveParam/ActiveReturn/Deindirect
- staged→collapseInternal 迁移 → 解锁 Unreachable/DoNothing/RedundBranch 接入

### P1（L1 模块核心算法）
- dynamic.cc 完整 BFS 多层扩展
- constseq.cc transform（CALLOTHER 替换）
- subflow.cc RuleSubvarAnd/RuleSubvarSubpiece applyOp

### P2（简化版→完整版）
- ActionFuncLink opStackLoad pcode 注入
- ActionActiveParam AncestorRealistic/ancestorOpUse
- ActionReturnRecovery 完整 RETURN 分析

### P3（L1 模块从零）
- G7 BreakTable/EmulateFunction
- 其他 L1 模块

---

## 当前反编译质量(2026-07-02 19:29 实测 `result/curl_cur.c` + `result/httpd_cur.c`)

> 本节从 AGENTS.md 迁移而来(2026-07-05),避免数据在 AGENTS.md 里过期。AGENTS.md 是规则文档,不放易过期的数据。

### curl(`curl_cur.c`,1281 行)
- `while`=39 / `for`=0 / `if`=149 / `switch`=0 ✅(`0fc0806` 把过度 switch 化从 18 降到 0)
- `goto`=2 ❌(仍是 `if (1) goto ;` 空目标**语法错误**)
- `uVar_<hex>`=0 ✅(07-02 差距报告里的 215 已修)
- `StackX_*`=98 次(19 个去重,仍残留)
- `param_N`=74 次(5 个去重)
- `memcpy`=0 ❌
- 结构骨架 diff 详见 `docs/archive/dated/QUALITY_GAP_2026-07-02.md`

### httpd(`httpd_cur.c`,Jun 30,1459 行)
- `while`=58 / `for`=0 / `switch`=15 / `goto`=0
- `uVar_<hex>`=**262 次(56 个去重)❌**(质量明显比 curl 差,此前文档「0 uVar」对 httpd 错误)
- `StackX_*`=49 / `param_N`=73

### 测试
**952/952 通过**(`cargo test --lib`,2026-07-05 核实)。`cargo test` 默认含 examples,需先 `cargo build --examples`。

### 已完成的核心移植(历史日志,2026-07-02)
identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, Datatype get_align_size/get_sub_type/get_hole_size/type_order, varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase, Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend + get_consume/set_consume/get_nzm/set_nzm + is_boolean_value, PcodeOp::is_calculated_bool, Funcdata op-edit API, get_booleanflip, bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set + functional_equality, expression.rs: TermOrder/AdditiveEdge/AddExpression, ActionRestructureVarnode, ~100 个 Rule struct, L1 模块骨架(14): condexe/transform/subflow/unify/constseq/opbehavior/rangeutil/userop/mem-state/float_emulate/pcodeinject/emulate/callgraph/signature, jumptable.rs L1→L2, override_rs.rs L1→L2, arch.rs L1→L2, database.rs L1→L2, findSpanningTree DFS 边分类 + F_BACK_EDGE 循环回边检测 + 回边保护, CFG 基本块划分修复(curl while 4→26).

### 2026-07-05 对齐审计(6 个并行 agent)
`docs/alignment_audit/INDEX.md` 汇总 8 个核心算法模块的 cross-review:73 MISMATCH / 68 PARTIAL / 36+ MISSING / 14 GLUE-UNJUSTIFIED / ~91 CITED-LINE-DRIFT。已修复 5 个 P0(参见 git log `10679d0`/`0c7ad89`/`8e11b3b`/`86c8e04`/`7eea43c`)。

> 注:旧 while/if 计数 KPI 已废弃(见 AGENTS.md 机制 B)。模块级算法对齐状态以 `ALIGNMENT_ROADMAP.md` 为准(其「最后核实」标注时效)。
