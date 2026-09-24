# DELTA_V2 — D10 流镜像落地后的双侧差集重测绘(Lane AU, 2026-09-22)

> 只读重测绘:不改 repo/worktree 源码,构建产物与报告全部落 `/dev/shm/rugra-tests/sb-integration/`。
> 逐节写盘防崩溃。

## §0 输入指纹(对齐账本要求)

| 项 | 值 |
|---|---|
| rugra 树 | worktree `/home/ls/Rugra-wt-sb-rust` @ **c5a8992**(`tool: driver flow mirror + bare-load dual switch behind env gates`) |
| 与 master 关系 | merge-base = 43f395b;master HEAD = 0348516。**本 worktree 不含 6107feb**(FUNCDATA-OPSTACKLOAD-CONTAIN-0001,在 `wt/sb-opstackload` 分支;master 也没有) |
| 镜像 env 组 | `RUGRA_STAGE_DRILL=1 RUGRA_STAGE_FUNC=next_url RUGRA_STAGE_DRILL_OUT=<path> RUGRA_FLOW_MIRROR=1 RUGRA_BARE_LOAD=1 RUGRA_ORACLE_FIXTURE_DATA=1`(env 名已从 examples/curl_decompile.rs:3549/3382/3463 逐一核实) |
| 输入二进制 | `examples/curl`,sha256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`(与两侧 META 一致) |
| oracle drill | `/dev/shm/rugra-tests/sb-drill/next_url.oracle.drill`(1293 blocks / 1019 records,oracle_commit e40ed130…376b,ladder=break_start_all_nodes) |
| oracle 投影 | `/dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection`(335 @BEGIN / ΣSNAP ops 96457 / producer f5d54a0a) |
| rugra 镜像 drill | 本目录 `next_url.rugra.drill.mirror`(producer rugra-tree-c5a8992,**连续两跑字节一致**) |
| rugra 镜像投影 | 本目录 `next_url.rugra.projection.mirror`(本 lane 在 c5a8992 重产;与 `sb-rust/next_url.rugra.projection.bare`(d402109 产物)逐字节相等,仅 META producer 行不同——M2b 之后驱动行为无漂移) |
| 消费端 | master `0348516` 的 `tools/drill_diff.py`(本 worktree 无该工具,按任务要求用 master 版) |

## §1 镜像态 drill 三数字(任务 1)

`@DONE applications=1519 records=1093 opactdbg_final=1093 perform_calls=480 nodes=78`

| 指标 | oracle | rugra 旧值(AL,非镜像,~5d95e2c 时代) | **rugra 镜像态(c5a8992)** | 镜像后变化 |
|---|---:|---:|---:|---|
| application blocks | 1293 | 1550 | **1519** | −31(仍 +226/+17.5% vs oracle) |
| native records(opactdbg_final) | 1019 | 1122 | **1093** | −29(仍 +74/+7.3% vs oracle) |
| 路径层 shared / oracle-only / rugra-only | — | 103 / 2 / 13 | **104 / 1 / 10** | shared +1,oracle-only −1,rugra-only −3 |

drill_diff 路径层原文(本目录 `drill_diff_mirror.txt` / `.json`):
`shared paths=104 (55 with equal counts), oracle-only=1, rugra-only=10`

### §1.1 oracle-only 残留:loadvarnode 仍在(如实记录,依赖未并入)

- 残留唯一 oracle-only 路径 = `universal:fullloop:mainloop:oppool2:loadvarnode ×9`(oracle 9 次应用,rugra 0 次,镜像前后都是 0)。
- **原因 = FUNCDATA-OPSTACKLOAD-CONTAIN-0001 修复不在本 worktree**:该修复(`funcdata.rs` opStackLoad/opStackStore 写 contain(ram) 而非 stack 自身 id,commit **6107feb**)位于 **`wt/sb-opstackload` 分支**,既不在 wt/sb-rust(merge-base 43f395b),也**不在 master**(master HEAD 0348516 同样没有)。任务背景说"修复在 master"与实际不符——准确状态:分支 `wt/sb-opstackload` 待集成。
- **依赖动作**:合并 6107feb(连带 9ab15c4 MERGE-GATHERPIECES-ISLEAF-0001,Cross-Review 仍 PENDING)后重跑本节命令,预期 oracle-only 归 0、rugra loadvarnode 0→9。

### §1.2 镜像后路径层翻转明细(vs AL 旧值 103/2/13)

| 路径 | oracle | 旧 rugra | 镜像 rugra | 判定 |
|---|---:|---:|---:|---|
| `…:oppool1:subvar_subpiece` | 2 | 0 | 2 | **oracle-only → shared(等数)**——D10 流镜像收敛项 |
| `…:oppool2:loadvarnode` | 9 | 0 | 0 | 仍 oracle-only(§1.1 依赖) |
| `…:oppool2:pushptr` | 0 | 3 | 3 | 仍 rugra-only(非新差) |
| `…:oppool2:structoffset0` | 0 | 1 | 1 | 仍 rugra-only(非新差) |
| `universal:dynamicsymbols` | 0 | 2 | 2 | 仍 rugra-only(非新差) |
| 其余 rugra-only 7 项 | 0 | — | notdistribute×10 / mainloop:unreachable×24 / cleanup:2comp2sub×6 / multnegone×6 / fullloop:deadcode×4 / directwrite×4 / ptrsubcharconstant×1 | 与 AL 列表一致,镜像不改变 |

结论:**镜像把 subvar_subpiece 从 oracle-only 翻为 shared,rugra-only 13→10 全部是镜像前已存在的旧差**(AL 的 13 项列表当时未列全 pushptr/structoffset0/dynamicsymbols,本节补齐计数)。

## §2 drill_diff 对照详情(任务 2)

### §2.1 首记录分歧:extrapopsetup 已收敛,推进到 prototypetypes

| | 旧值(AL) | 镜像态 |
|---|---|---|
| 公共前缀 | 2 行(constbase) | **21 行(10 个完整 op 对)** |
| 首分歧位置 | @BEGIN 4 extrapopsetup,首触 op `0x505d:2ce` vs `0x50ce:2ce` + 0x2534/0x50fa 尾跳建模差 | **@BEGIN 5 universal:prototypetypes** |
| 首分歧内容 | — | oracle `0x00005212:28a: return(#0x0)` vs rugra `return(#0x0) RAX(free)` |

- extrapopsetup 的首触序旋转、`0x2534:2d6` vs `0x50fa:2d6` RSP+8 归属差(AL §1 的 D10 家族)**已随流镜像全部消失**——与 raw ops 717=717 一致。
- 新首分歧 = RETURN 挂 RAX 第二输入(投影侧同域:ordinal 5 seq 6,`2534:2cc RETURN in=c:1:4,n:register:0:8`)。drill 里首现在 `0x5212:28a` 而非 2534,是因为 drill 只记录被触改的 op,序上先触到 0x5212 的 RETURN——**同一族差(RETURN-ARTIFICIAL-RAX-0001)**。

### §2.2 记录内容分类(paired shared-path occurrences)

`compared line pairs=8336, differing=3843`:

| 类 | 对数 | 归因 |
|---|---:|---|
| opcode_name | 3240 | **drill 格式器差,非管线差**:oracle CALL 打 `call ffunc_0x2370(free)` vs rugra `call i0x2370(free)`(= 已登记 SB-DRILL-FSPEC-NAME,fspec 名字层) |
| const_width | 217 | `#0x0` vs `#0x0:4` 等(HERITAGE-SUBPIECE-CONST-WIDTH-0001 族;全文件 census:#0x0 426→746、#0x0:4 637→292、#0x3 6→100、#0x4 0→60、#0xffffffffffffffb0 0→24) |
| other | 318 | 未分类(heritage 前后 op 集序差异为主) |
| seqnum_drift | 62 | uniq/time 漂移(如 `5c3` vs `5c5`,+2 恒差——placeholder 创建计数) |
| dead_marker | 6 | `**` dead 标记位错位(同 op 集序差的投影) |

### §2.3 @DONE 统计差(信息项)

`applications 1293 vs 1519`、`opactdbg_final 1019 vs 1093`、`perform_calls 311 vs 480`、`nodes 232 vs 78`(ladder 机制不同,oracle break_start_all_nodes 逐节点,rugra break_start_frontier——非管线差)。

## §3 事件数 335 vs 479 归因初查(任务 3,投影层)

### §3.1 路径集完全一致,差异全在"遍数"

`distinct paths: oracle=76 rugra=76 shared=76 oracle_only=0 rugra_only=0`(本目录 `begin_path_table.txt`)。
+144 个 @BEGIN 事件的**精确分解**(脚本 `begin_path_counts.py`):

| 类别 | 贡献 | 对应遍数差 |
|---|---:|---|
| mainloop children(每 pass 23 个子节点) | **+92** | **mainloop passes 8 → 12(+4)** |
| stackstall 内部子节点(每内迭代 5 个) | **+30** | **stackstall 内迭代 12 → 18(+6)** |
| fullloop 尾部 9 路径 | **+9** | **fullloop rounds 3 → 4(+1)** |
| mainloop:unreachable(每 pass ×2,两处实例同名) | +8 | +4 passes × 2 |
| stackstall 组括号(每 pass 1) | +4 | +4 passes |
| mainloop 组括号(每 round 1) | +1 | +1 round |
| **合计** | **+144** | 92+30+9+8+4+1 |

三层 repeatapply 不动点全部多跑:**fullloop 多 1 轮、mainloop 多 4 pass、stackstall 多 6 内迭代**。逐 mainloop-round 的 pass 数:oracle `[4,3,1]`,rugra `[4,4,3,1]`(脚本 `pass_changes.py`,产物 `pass_oracle.txt` / `pass_rugra.txt`)。

### §3.2 每轮变更对照表(谁多报了 changes)

oracle(8 pass;数字=result count):

| round | pass | 变更应用 |
|---|---|---|
| R1 | p1 | activeparam=9, returnrecovery=4, **stackstall/oppool1=863**, redundbranch=1, blockstructure=9, oppool2=22 |
| R1 | p2 | activeparam=9, restructure_varnode=1, oppool1=85 |
| R1 | p3 | oppool1=15 |
| R1 | p4 | (clean → mainloop 收敛) |
| R2 | p1 | blockstructure=3, oppool2=4 |
| R2 | p2 | oppool1=12 |
| R2 | p3 | (clean) |
| R3 | p1 | (clean → fullloop 收敛);R2 尾部 starttypes=1+activereturn=9 是 R3 存在的原因 |

rugra 镜像(12 pass):

| round | pass | 变更应用 | 与 oracle 对应 pass 的差 |
|---|---|---|---|
| R1 | p1 | activeparam=9, **oppool1=826**, blockstructure=8, oppool2=13 | 无 returnrecovery=4/redundbranch=1;oppool2 13 vs 22 |
| R1 | p2 | activeparam=9, restructure_varnode=1, oppool1=55 | oppool1 55 vs 85 |
| R1 | p3 | **activeparam=9(第 3 次)**, restructure_varnode=1, oppool1=32 | oracle 此 pass 仅 oppool1=15 → **多出 activeparam 重燃+restructure_varnode** |
| R1 | p4 | (clean) | |
| R2 | p1 | blockstructure=5, **constantptr=3**, oppool2=18 | **多 constantptr=3;oppool2 18 vs 4** |
| R2 | p2 | **oppool1=67**, **oppool2=8** | oppool1 67 vs 12;**多 oppool2=8** |
| R2 | p3 | **oppool2=1** | oracle 此 pass 已 clean → **多 1 个 pass(p4)** |
| R2 | p4 | (clean) | |
| **R3(整轮新多)** | p1 | **oppool1=4, blockstructure=5** | oracle R3 全 clean |
| **R3** | p2 | **oppool1=31** | 同上 |
| R3 尾 | tail | **returnsplit=1**(seq 295) | oracle 尾部无变更 |
| R4 | p1 | (clean → fullloop 收敛) | 整轮因 R3 有变更而存在 |

### §3.3 top3 事件差路径(按 |delta|)+ 规则层 top

投影层(结构性,均匀):① 全部 23 个 mainloop 子节点各 +4(unreachable +8)——mainloop 多 4 pass;② stackstall 5 个池子(oppool1/multicse/shadowvar/deindirect/stackptrflow)各 +6——stackstall 多 6 内迭代;③ fullloop 尾部 9 路径各 +1——fullloop 多 1 轮。
drill 规则层(谁在多干活):**ptrarith +19(4→23)**、**boolnegate +16(17→33)**、**termorder +12(5→17)**;其次 deindirect/multicse/condnegate/shadowvar/stackptrflow/addmultcollapse/propagatecopy 各 +6,activeparam/blockstructure 各 +4;负向 equal2zero −6(13→7)、subvar_zext −5、lessequal −3。

### §3.4 Action 域假设清单(按可能性排序,未做源码级深挖)

- **H1(最强,直接解释 +1 fullloop 轮)**:rugra 第 3 轮 mainloop 仍报变更——stackstall/oppool1 晚期余震(67@R2p2、4+31@R3)+ blockstructure=5 晚期重排,而 oracle R3 全 clean。域:**oppool1 规则族(earlyremoval/propagatecopy)+ blockstructure**。旁证:最终快照 COPY 171 vs 12(§4)——拷贝链 churn 未熄火。
- **H2**:R2 多 1 个 pass 由 **oppool2 晚期单发(oppool2=1@R2p3)** 造成,且 ptrarith 4→23 全程多 19 次——**RULE-PTRARITH-ADDTREE-0001(AddTreeState 把 PTRSUB 溶回 INT_ADD)** 家族;最终银行 CROSSBUILD 18 vs 0 同向。
- **H3**:R1p3 的 **activeparam 第 3 次重燃(count=9 每次相同)**——ACTIVEPARAM-COUNT-9V2-0001/D14 域:9 个 active-param 写第一轮"没写死",需单函数无签名双态开关裁决是否签名库环境假阳性。
- **H4**:**returnsplit=1 仅 rugra 出现(fullloop 尾部)**——ActionReturnSplit 对人工 RETURN+RAX 输入结构(2534:2cc)做出反应,指向 RETURN-ARTIFICIAL-RAX-0001 的下游涟漪;若该登记项修复,预期 returnsplit 4→3、R3 可提前收敛。
- 反向注记:oracle 有 redundbranch=1/returnrecovery=4,rugra 无—— Rugra 并非纯"多跑",R1 的组成也有替换差,收敛判定需整轮 count==0 而非逐项相等。

## §4 ΣSNAP 银行膨胀(96457 vs 152809)

| 指标 | oracle | rugra 镜像 | 差 |
|---|---:|---:|---|
| @SNAP 数(=事件数) | 335 | 479 | +144 |
| ΣSNAP ops | 96457 | 152809 | **+56352(+58.4%)** |
| 平均每快照 ops | 287.9 | 319.0 | +10.8% |
| 首快照(universal:start) | **717** | **717** | **0(镜像收敛实证)** |
| 末快照(universal:stop 前) | 255 | 465 | **+210(+82%)** |
| 前 10 快照均值 | 951.4 | 951.4 | 0(早期完全同步) |

分解:ΔΣ = +56352 ≈ **事件数效应 +41447(73.6%)**(144 × oracle 均值 287.9)+ **每快照银行变厚 +14905(26.4%)**。即膨胀主体是"多跑的事件 × 每事件全量快照",银行本身只在后期发散。

**末快照 opcode census(银行变厚的真凶)**:

| opcode | oracle | rugra | Δ |
|---|---:|---:|---:|
| COPY | 12 | **171** | **+159** |
| CROSSBUILD(PTRSUB 族) | 0 | 18 | +18 |
| CAST | 33 | 43 | +10 |
| LABEL(PTRADD 族) | ≤5 | 11 | +6 |
| INT_EQUAL vs INT_NOTEQUAL | 5(NEQ) | 9(EQ) | 布尔规范化反向(boolnegate 域) |
| DELAY_SLOT / BUILD / CBRANCH / CALL / LOAD | 34/34/16/8/24 | 38/35/16/8/22 | ~持平 |
| INT_ADD | 41 | 32 | −9 |

结论:**COPY 滞留(+159)是银行膨胀的单一主导项**——与 H1(oppool1 晚期 churn)互为表里:多余拷贝既推高每快照均值,又因不被 earlyremoval/propagatecopy 清干净而持续触发下一轮变更,形成"多轮×厚银行"复合膨胀。CROSSBUILD +18 与 H2(PTRSUB 溶解差)同族。

## §5 Phase 3 punch list v2(任务 4,合并全部已登记未修缺口)

> 优先级:P0 阻塞集成 > P1 行为真差 > P2 裁决/登记 > P3 工具格式。owner 为"建议域",最终由 root 按 write-set 排他分配。

| # | ID(状态) | 现象(本报告证据) | 依赖 | 建议 owner 域 | 验证方法 |
|---|---|---|---|---|---|
| 1 | **FUNCDATA-OPSTACKLOAD-CONTAIN-0001**(已修于 `wt/sb-opstackload`@6107feb,**未集成**) | 镜像 drill 唯一 oracle-only 路径 `oppool2:loadvarnode ×9`(rugra 0 次) | merge 6107feb 入 master/主干;连带 #2 | root 集成(funcdata.rs opStackLoad/Store contain) | 合并后重跑 §1 命令:oracle-only 1→0,rugra loadvarnode 0→9;curl E2E defects=0(AO 分支已验 725→1048) |
| 2 | **MERGE-GATHERPIECES-ISLEAF-0001**(同分支@9ab15c4,已修,**Cross-Review PENDING**) | #1 解锁后 main 在 ActionMergeRequired 256MB 栈溢出(AO 复现) | #1;merge.rs 属核心算法白名单,须机制 C 复核后才能并 | root + 独立 reviewer | reviewer 重读 merge.cc:1381-1404 比对 isLeaf 五判定;并后 curl 全量 E2E |
| 3 | **RETURN-ARTIFICIAL-RAX-0001**(P1,新登记未修) | 消费端/drill 双侧首分歧:ordinal 5 seq 6 prototypetypes,`2534:2cc RETURN` rugra 多第二输入 `n:register:0:8`(drill 首现在 `0x5212:28a return … RAX(free)`);oracle 以 INDIRECT [create] 群表达 | 无硬依赖;疑似 #7 的近亲 | ActionActiveReturn/returnrecovery 域(coreaction) | 修复后 drill 首分歧推进过 prototypetypes;投影 ordinal>5 |
| 4 | **ACTION-TRAVERSAL-144-0001**(建议新登记,P1) | 事件 335 vs 479:fullloop 3→4 轮、mainloop 8→12 pass、stackstall 12→18 内迭代(§3.1 精确分解 +144) | #3(returnsplit 涟漪)、#5(COPY churn)、#6(activeparam)、#8(ptrarith) | ruleaction(oppool1 族 earlyremoval/propagatecopy)+ coreaction(blockstructure) | `pass_changes.py` 逐轮表收敛到 oracle 模式 [4,3,1];@BEGIN 总数 479→335 |
| 5 | **BANK-COPY-159-0001**(建议新登记,P1,可与 #4 合并追踪) | 末快照 465 vs 255 ops,COPY 171 vs 12(+159)主导;ΣSNAP +56352=73.6% 事件数 × 26.4% 银行增厚 | #4 同根;loadvarnode 未并(#1)使 stack LOAD 占位滞留 | ruleaction(earlyremoval/propagatecopy/deadcode) | 末快照 census COPY 171→~12;ΣSNAP 152809→~96457 |
| 6 | **ACTIVEPARAM-COUNT-9V2-0001 / D14**(P1,登记未决) | 投影 @END seq 18 activeparam count oracle=9 vs rugra=2(旧);镜像态两侧均 9 但 rugra 重燃 3 次 vs oracle 2 次 | 需"单函数无签名"双态开关裁决(签名库环境假阳性?) | coreaction(activeparam)+ fspec 域 | 双态探针 [9,9,0] 逐点一致 + maxdelay 实值(RCA-2: oracle maxpass 1 vs rugra 2) |
| 7 | **RULE-PTRARITH-ADDTREE-0001**(P1,登记未修) | drill ptrarith 4→23(+19);末快照 CROSSBUILD 18 vs 0;oppool2 晚期单发(=1@R2p3)多造 1 个 mainloop pass | DWARF 环境不对称污染倍数,先钉平镜像 env | ruleaction(RulePtrArith AddTreeState) | 镜像 drill ptrarith 23→4;CROSSBUILD 18→0 |
| 8 | **FUNCDATA-SPACEID-WIDTH-0001**(P1,登记未修,条件 2 未闭) | op_stack_load 发 size=1 spaceid 常量 vs Ghidra size=8;765 个 LOAD 槽 `c:5:1` 被发射器尺寸门挡 | main +24 函数级归因绑 R1c/R2a 族,root 集成阶段补齐 | funcdata + root 归因 | 修后 `c:5:1` → `c:5:8` 渲染入投影;main 差 24 行逐函数对账归零 |
| 9 | **HERITAGE-SUBPIECE-CONST-WIDTH-0001**(P2,登记未修) | drill const_width 217 对差(`#0x0` vs `#0x0:4`;#0x3 6→100、#0x4 0→60) | 无 | heritage(newConstant(4) 约定) | const_width 分类计数 217→0 |
| 10 | **MIRROR-ENVS-CANONICAL-0001 + 镜像 E2E +113**(P2,裁决项) | raw-BFD 镜像 vs golden(thunk analyzer)PLT 名字层差,E2E +113 | root 翻转默认前必须裁决 | root + C-alignment(driver) | 双态 golden 重建或名字层归一方案落地后 E2E 差分 113→0(或书面豁免) |
| 11 | **SB-DRILL-FSPEC-NAME**(P3,工具格式) | drill 3843 对差中 3240 对是 `call ffunc_0x2370` vs `call i0x2370` 拼写(84%) | 无 | drill 发射器(examples,非 src) | ffunc_/i0x 统一后 opcode_name 类 3240→~0,真实管线差从 603 对裸露 |

依赖图(DAG):#1→#2(集成序);#3、#6、#7 为 #4 的上游候选;#5 与 #4 同根可同 lane;#1 也是 #5 的部分原因(loadvarnode 不触发→stack 占位 LOAD 滞留);#11 是观测噪声消除,建议最先做(成本最低、解锁真实差集读数)。

## §6 复现命令

```bash
cd /home/ls/Rugra-wt-sb-rust && cargo build --profile fast-release --example curl_decompile
# drill(镜像态)
RUGRA_STAGE_DRILL=1 RUGRA_STAGE_FUNC=next_url \
RUGRA_STAGE_DRILL_OUT=/dev/shm/rugra-tests/sb-integration/next_url.rugra.drill.mirror \
RUGRA_FLOW_MIRROR=1 RUGRA_BARE_LOAD=1 RUGRA_ORACLE_FIXTURE_DATA=1 \
./target/fast-release/examples/curl_decompile
# 投影(镜像态)
RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=next_url \
RUGRA_STAGE_PROJ_OUT=/dev/shm/rugra-tests/sb-integration/next_url.rugra.projection.mirror \
RUGRA_FLOW_MIRROR=1 RUGRA_BARE_LOAD=1 RUGRA_ORACLE_FIXTURE_DATA=1 \
./target/fast-release/examples/curl_decompile
# 消费端
python3 /home/ls/Rugra/tools/drill_diff.py \
  /dev/shm/rugra-tests/sb-drill/next_url.oracle.drill \
  /dev/shm/rugra-tests/sb-integration/next_url.rugra.drill.mirror --top 15
python3 begin_path_counts.py /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection \
  next_url.rugra.projection.mirror   # 335 vs 479 事件差精确分解
python3 pass_changes.py <oracle.projection> O && python3 pass_changes.py <mirror.projection> R
```

附件(本目录):`next_url.rugra.drill.mirror`、`next_url.rugra.projection.mirror`、`drill_diff_mirror.{txt,json}`、`begin_path_table.txt`、`begin_path_counts.py`、`round_analysis2.py`、`rounds_{oracle,rugra}.txt`、`pass_changes.py`、`pass_{oracle,rugra}.txt`、`mirror_drill.std{out,err}`、`mirror_proj.stderr`。
