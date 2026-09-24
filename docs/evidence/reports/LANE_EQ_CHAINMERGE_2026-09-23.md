# Lane EQ (sb-chainmerge) — 停车链(DL/DN/DP/EC/EH) 并入 master 的测试合并与集成裁决数据

> **Round 2（快进复测，2026-09-23 晚）已追加**：master 前进到 983e0fc9 后的第二轮合并
> 与复测见文末 §7-§9；**round 1 的一处结论已修正**（main "完成"仅限 default 模式，
> stage-emitter 模式在两轮合并态均死锁——见 §8 修正块）。

- 日期: 2026-09-23 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/chainmerge, branch **wt/chainmerge**
- **Round 1 merge commit: 24a31e7deedb94ee9a7c4884ddaa871ef021b90e**（merge-base af98f92e）
  - side A = master **6b0c1b89**（任务锁定基线；EK bootstrap usepoints 等 43 commit）
  - side B = chain tip **wt/boomattr@1c7bde2b**（DL RC1/RC2 + DP RC3 + EC + 4c53bfeb + EH r2；9 commit）
- **Round 2 merge commit: 736982f2c075bf1516ad5b365654e2095a5abfc2**（= 24a31e7d × master 983e0fc9）
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-chainmerge（fast-release）
- 写域: 仅本 scratch worktree + /dev/shm/rugra-tests/sb-chainmerge/。**未动 master**。


## 1. 冲突清单与解决

`git merge --no-ff --no-commit wt/boomattr` — **唯一文本冲突: docs/api/funcdata.md**，
双侧 2026-09-23 日志条目并集解决（master 的 RET-OP3-0001 波及条目 + SETVARNODE-SCOPELOCAL-0001
条目在前，链侧 BOOMATTR adjustInputVarnodes r1+r2 条目在后）。

源文件全部 auto-merge，逐文件做了函数级区域核对（auto-merge ≠ 语义安全，已验证）：

| 文件 | master 侧改动区域 | 链侧改动区域 | 交叉验证 |
|---|---|---|---|
| src/coreaction.rs | ActionRestructureVarnode（EK bootstrap）/ActionSetCasts/ActionConditionalConst/ActionNodeJoin/tests | ActionConstbase/ActionInputPrototype/ActionParamDouble/StackSolver/ActionStackPtrFlow/ActionExtraPopSetup | **函数级零重叠**；EK `reset_local_window(fd)`@1496 与链 `adjust_input_varnodes(space,offset,size)` 调用@ActionUnjustifiedParams 均在位。无同函数 case，"链侧 EH 完整版为基底"不适用——两侧本就不在同一函数 |
| src/funcdata.rs | set_varnode_properties（EE ScopeLocal 腿）/node_join_create_block（EB） | adjust_input_varnodes（EH 空间感知化，10408-10510 区域） | 零重叠 |
| src/disasm/x86_lift.rs | RET 臂（DU2 三 op 模板）@~4724 | CALL 臂（DL RC1 push 序列）@~4649 | 不同 match 臂，两模板均在位 |
| src/fspec.rs / src/ruleaction.rs / src/prettyprint.rs / examples/httpd_decompile.rs | merge-base 后 master 零改动（已核实 `git diff af98f92e master` 为空） | RC3 effective_extrapop/4c53bfeb/EC/RC2 | 合并态=链侧逐字节（diff-vs-chain=0） |
| docs/TODO_BOARD.md | EK/DY/DQ/ED/EB/EE/DX/DS/DU2/DV 等行 | EH/DL/DP 行 | auto-merge 双侧行取并集，均在位 |

## 2. 合并态三门禁（default 模式，两轮运行逐字节相同）

| 语素 | 合并态 | master 6b0c1b89（本 lane 亲测 git archive 复现） | 链 r3 归档（sb-boomattr） |
|---|---|---|---|
| curl | **2516/0/0**（124/124 fn） | 2516/0/0（=任务口径，逐函数全等） | 2684/0/0（124/124） |
| httpd | **2539/0/0**（29/29 fn，main 完成于 ~6.6s） | 2335/0/0（29/29，=任务口径） | 2099/0/0（**仅 28 fn——链态 main 挂起**） |

- curl 合并态 **与 master 6b0c1b89 逐函数完全相同**（12 个函数相对链改善：main −44、
  parseconfig.constprop.0 −27、getparameter −25、match_url −23、glob_set −12、my_fwrite −8、
  myprogress −6、glob_range −5、helpf −4、SetHTTPrequest.part.0 −2、file2string −2、
  my_get_token −2）；**对链零回退**，对 master 零变化。
- httpd 合并态 vs master：+204 skeleton（defects/numbering 双零）。逐函数 delta 与归因见 §4。
- ⚠️ 运行噪声备注：首次 curl 全量运行在 glob_set→glob_range 之间停滞 25min 被外部超时截断
  （69/124）；后续三次完整运行均 35-38s 且逐字节相同（含 glob_range 单函数 <240s）。
  判定为一次性环境失速（/dev/shm 压力或调度），非合并态可复现行为；证据 curl_merged.stderr(截断)
  vs curl_merged2/3.stderr。

## 3. 三投影 MATCH（RUGRA_MIRROR=1 全家 env，merge commit 后重生成，producer=24a31e7d）

| 投影 | oracle 钉 | 结果 |
|---|---|---|
| next_url | /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection | **MATCH**（非 META diff 行 = 0） |
| match_url | /dev/shm/rugra-tests/sb-oracle/curl.match_url.oracle.projection | **MATCH**（0） |
| parseconfig.constprop.0 | /home/ls/Rugra/.fixture-staging/sb-parseconfig/curl.parseconfig.oracle.projection | **MATCH**（0） |

stage 体与 oracle 逐字节相同，仅 side/producer 两条 META 身份行（4 diff 行）按定义差异。

## 4. 函数级异常回退登记（vs 两侧基线取差）

**curl：无任何回退**（vs master 全等；vs 链 12 改善 0 回退）。

**httpd vs master 6b0c1b89（+204）**，逐个归因：

| 函数 | master→merged | 归因 |
|---|---|---|
| main | 668→891 (+223) | 链态 main 原本**挂起**（HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001 家族），合并态完成但骨架更大：puVar 临时物化 +160、uRam 裸全局 +26、extraout +28——链侧 RC1(CALL push 模板)+RC2(cspec 挂载)+RC3(extrapop 写回)+EH(参数族) 在 httpd 路径的预期形态面，master 从未有这些；**挂起解除本身是合并态新增能力**。骨架差归属 GOLDEN-CONTRACT-PUSHABSORB-0001（root 开放裁决）+ HTTPD-MAIN 家族 |
| ap_fini_vhost_config | 384→404 (+20) | 链态该函数 +113（411）；master 侧内容（EE/EK 等）已收回 93。残余为链侧 in_RSI/extraout 原始参数命名族（EH lane residual ① BOOMATTR-INSTACK-SYMATTACH-0001 同族） |
| ap_ht_time | 80→96 (+16) | 链态 140，master 侧收回 44；残余同上族 |
| ap_vhost_iterate_given_conn | 37→48 (+11) | 链态 28 **优于两侧**——三向各有形态差，非单调劣化；raw-param 命名族 |
| ap_strcmp_match / ap_strcasecmp_match | +8 / +7 | 同族（链 38/51 → 合并 54/72） |
| ap_os_is_path_absolute / ap_parse_vhost_addrs | +4 / +4 | 同族；ap_parse_vhost_addrs 链态 311 → 合并 54，master 侧大幅收回 |
| ap_field_noparam / ap_make_dirstr_parent / ap_make_dirstr_prefix / ap_set_name_virtual_host | +2 ×4 | 同族小幅 |
| （改善侧）ap_pregsub −31 / ap_update_vhost_from_headers −32 / ap_update_vhost_given_ip −10 / ap_getparents −9 / ap_getword −8 / ap_init_vhost_config −2 等 10 函数 | | 链侧内容净收益 |

**符号族判别**（三向 grep 计数）：`in_RSI`×41、`extraout_*`×42 在合并态与链态同源
（链 42/22，master 0/0）→ **链固有**，非合并伪影；`in_RIP`×21 **仅合并态出现**（两侧皆 0）=
真合并交互伪影（master 侧某改动使 RIP 槽输入在链侧 RC1/RC3 世界里存活到打印），但所在函数
相对 master 多为改善（ap_init_vhost_config 16→14、ap_fini 384→404 中 RIP 命名 vs master 的
param_1 命名等价形态差），oracle 正典对该族用 DAT_ 绝对地址（analyzeHeadless 桥接层），
Rugra 两侧均未达。登记为 **CHAINMERGE-INRIP-PRINTFAMILY-0001**（P3，观察项，root 裁决
GOLDEN-CONTRACT 时一并考虑）。

## 5. 集成裁决建议（root 终裁输入）

**可并，条件性**：
1. curl 侧完全无争议：合并态=master 逐函数全等、对链纯改善、三投影 MATCH、双零。
2. httpd 侧 +204 skeleton 全部落在链侧 httpd 行为族（RC1-3+EH 已知开放域）内，
   defects/numbering 双零，且**解除了链态 main 挂起**（合并态 6.6s 完成）——即链并入 master
   不引入任何 master 侧回归机制，只是把 httpd 从"master 形态"移到"链形态"（部分函数更差、
   10 函数更好、main 从挂起变可用）。
3. 建议裁决顺序：root 先裁 GOLDEN-CONTRACT-PUSHABSORB-0001（canonical vs 库级准绳）——
   若库级为准，httpd 骨架差大部分豁免；若 canonical 为准，in_RSI/extraout/in_RIP 族需要
   BOOMATTR residual ①② 车道先行。
4. **前瞻冲突**：master 在本 session 期间前进到 983e0fc9（EN union-resolve + EO2 TypeFactory
   httpd driver 挂载）。wt/chainmerge 并入新 tip 时 `examples/httpd_decompile.rs` 将冲突
   （链 RC2 cspec 挂载 vs EO2 TypeFactory 挂载），`src/unionresolve.rs`/typeprop 管线亦需
   复核 EH ActionInputPrototype 与 EN 生产者点的相互作用。参考探针：本 lane 对 983e0fc9 的
   亲测基线 curl 2512/0/0、httpd 2225/0/0（master6b 归档：master_curl/master_httpd.*）。

## 6. 产物清单（/dev/shm/rugra-tests/sb-chainmerge/）

- curl_merged2.c / curl_merged3.c（合并态 default，逐字节相同）+ *.compare.txt
- httpd_merged.c / httpd_merged2.c + *.compare.txt
- final.{next_url,match_url,parseconfig}.projection（producer=24a31e7d）+ merged.*.projection（pre-commit 版）
- master6b_{curl,httpd}.c + compare（6b0c1b89 锁定基线复现）/ master_{curl,httpd}.c + compare（983e0fc9 前瞻基线）
- tmp/chain_compare.txt、tmp/chain_httpd.compare.txt（链 r3 归档复算）
- master6b-src/、master-src/（git archive 探针源，可回收）
- curl_merged.stderr（截断运行证据）

target 目录 /dev/shm/rugra-targets/sb-chainmerge{,-master,-master6b,-m24a} 保留至 root 集成后回收。

---

# Round 2 — 快进复测（wt/chainmerge@736982f2 = 24a31e7d × master 983e0fc9）

## 7. 冲突与共存（round 2）

唯一文本冲突 **examples/httpd_decompile.rs**（预期内）：链 RC2 cspec 挂载 vs EO2
TypeFactory 挂载。按"两者共存、以 curl 驱动完整 init 链为形态"解决：
- 主体 = RC2 全链（cspec 进共享 `store` + register_tag + archid + register_xref +
  commentdb + **TypeFactory 块**（fresh registry + data_organization decode +
  setup_sizes + set_types）+ PcodeInjectLibrary/UserOpManage + parse_compiler_config
  → defaultfp 断言）——与 curl_decompile.rs worker 形态逐项相同（已对照
  curl 驱动 1861-2014 行核实）。
- EO2 的功能性贡献（init 无条件建 TypeFactory，architecture.cc:1398）被 RC2 全链
  **包含**（RC2 先于 EO2 独立落了同一修复）；EO2 的
  TYPEPROP-NONSETTLING-HTTPD-0001 根因注释折入注释块；EO2 的 fresh
  cspec_store/registry 变体被共享 store 形态取代。
- 其余 auto-merge：新 master coreaction hunks（ActionSetCasts cast producer 站点，
  6b0c1b89 坐标 4796-5234）与 ruleaction hunks（RulePieceStructure 13931+）均落在
  链从未触碰的函数；unionresolve(+453)/rugra_decompile_func(+48) master 独占；
  funcdata/x86_lift/fspec/prettyprint 新 master 零改动。**函数级零重叠**。

## 8. 三门禁（round 2，双轮运行逐字节相同）

| 语素 | round2 合并态 | 983e0fc9 基线（亲测） | round1 合并态 | Δ 解读 |
|---|---|---|---|---|
| curl | **2512/0/0**（124/124） | 2512/0/0 | 2516/0/0 | **逐函数全等于 983e0fc9**（delta 表为空）；EN/EO2 的 main −4（575→571）完整流入合并态；对链仍 12 函数改善 0 回退 |
| httpd | **2539/0/0**（29/29） | 2225/0/0 | 2539/0/0（逐字节相同） | **EO2 TypeFactory × 链交互 = NO-OP**（RC2 已含 factory）；绝对数字不动，基线降 110 → 缺口从 +204(6b) 变 +314(983) |

**EO2/EN 与链 main 物化(+223)交互的裁决问题：不变**。httpd main 在合并态 default
模式 <1s 完成全body（diff=891），EN 的 httpd 改进在链路径主导的函数上不继承：

| 函数 | 6b0c1b89 | 983e0fc9 | 合并态 | EN delta | 继承? |
|---|---|---|---|---|---|
| ap_fini_vhost_config | 384 | 298 | 404 | −86 | **否**（链路径；合并比两 master 都差） |
| ap_update_vhost_from_headers | 212 | 188 | 180 | −24 | 值优于 983（链 −32 > EN −24） |
| ap_pregsub | 212 | 211 | 181 | −1 | 值优于 983（链 −31） |
| ap_getparents | 137 | 130 | 128 | −7 | 值优于 983 |
| ap_ht_time | 80 | 86 | 96 | +6 | 否（+16 vs 6b） |
| ap_make_dirstr_prefix | 42 | 44 | 44 | +2 | 是 |

## 9. ⚠️ 修正与新登记：HTTPD main stage-emitter 死锁（两轮合并态均有）

**Round 1 报告修正**：前报"合并态 main 完成/挂起解除"**仅对 default 模式成立**。
stage-projection/mirror 单函数模式（RUGRA_MIRROR=1 + RUGRA_STAGE_PROJ=1 +
RUGRA_STAGE_FUNC=main）在**两轮合并态均死锁**：

| 树 | 同调用 | wall | 投影文件 |
|---|---|---|---|
| master 6b0c1b89 | ✅ 完成 | 4.4s | 72.8MB 完整 |
| master 983e0fc9 | ✅ 完成（"Unknown calling convention" 警告=无 defaultfp） | 6.7s | 完整 |
| merge 24a31e7d | ❌ 死锁 | >120s | 冻结于 76745730B |
| merge 736982f2 (round2) | ❌ 死锁 | >600s | 冻结于 76745763B（复跑同值，确定性） |

- 死锁签名：最后 stderr `[BLOCKSTRUCT] main finalize_structure: 89 -> 12`，
  CPU ≈ idle（600s wall / 3.1s user），文件大小冻结 → 硬死锁非慢发射；
  驱动设计上 stage-emitter 模式 rx.recv() 无限等待（httpd_decompile.rs:993-1004
  注释明示），default 模式才有 15s 看门狗。
- 归因：**链侧内容**（DL/DP/EC/EH 族）破坏 httpd main 的 emitter frontier
  stepping——两纯 master 均完成、两轮合并态均挂，与 master 侧内容（EK/EE/EN/EO2）
  无关。即已登记 **HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001 家族在合并态持续存在，
  仅 stage-emitter 模式**（default 模式 main <1s 完成、891 全 body）。根因在链侧
  stepping 机制与某 Action 的交互，超出本 lane 裁决域，维持原登记 + 本数据点。

## 10. Round 2 三投影 MATCH（producer=736982f2 自证）

next_url / match_url / parseconfig.constprop.0：非 META diff = 0，**全 MATCH**
（eq2.final.*.projection）。

## 11. 终裁数据包（root 输入，两轮合并汇总）

1. **curl 侧零争议**：round2 合并态逐函数 ≡ 983e0fc9、2512/0/0、对链纯改善、
   三投影 MATCH、双零、确定性复跑通过。
2. **httpd 侧**：+314(983)/+204(6b) skeleton 全落链侧 httpd 行为族（RC1-3+EH 已知
   开放域），defects/numbering 双零；10 函数改善（多数优于新 master）；EO2/EN 与链
   无新增负面交互（TypeFactory 交互=NO-OP；EN httpd 增益在链路径函数上不继承，
   其中 ap_fini 合并态劣于两 master）。
3. **新风险登记**：stage-emitter 模式 httpd main 死锁（§9，链侧，两轮均有）——
   影响 fixture 采集（--func/--stage 模式）不影响 default 语素门禁；建议随
   HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001 一并由 root 排期根因车道。
4. **建议：条件可并**。curl 全量可并；httpd 并入不引入 master 侧回归机制，但
   (a) GOLDEN-CONTRACT-PUSHABSORB-0001 裁决前 httpd 骨架差无法定性，
   (b) ap_fini_vhost_config +106（劣于两 master）与 stage-emitter main 死锁
   建议作为并车前置或紧随车道（BOOMATTR residual ① 族 + stepping 根因）。

## 12. Round 2 产物（/dev/shm/rugra-tests/sb-chainmerge/）

- eq2_curl.c / eq2_curl_r2.c + eq2_curl.compare.txt（2512/0/0，确定性）
- eq2_httpd.c / eq2_httpd_r2.c + eq2_httpd.compare.txt（2539/0/0，确定性）
- eq2.final.{next_url,match_url,parseconfig}.projection（producer=736982f2，全 MATCH）
- 死锁矩阵证据：eq2.httpdmain.timing.{projection,err}（600s 冻结）、
  growtest.{projection,err}（尺寸冻结曲线）、m24a.httpdmain.*（round1 同挂）、
  m6b.httpdmain.* / m983.httpdmain.*（两 master 完成）
- 探针源与 target：master-src(983e0fc9)、master6b-src(6b0c1b89)、m24a-src(24a31e7d)
  + 对应 /dev/shm/rugra-targets/sb-chainmerge-{master,master6b,m24a}（root 集成后回收）

