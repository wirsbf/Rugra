# 重启触发面 parity 测绘（TRIGFACE，2026-09-26）

> 车道 wt/trigface（基=master `d4347dcd`）。票源：PIPE-RESTART-0001 剩余项 d +
> GEN4-SQ-RAMNAME-0001 解锁链 ③。oracle=锁定 commit `e40ed130`（12.0.4）。
> 方法：锁定 cpp 树 `git archive` 提取至内存盘打 stderr 探针后构建（oracle 检出零改动，
> preflight 锁 commit+tree 校验通过）；Rugra 侧临时 eprintln 探针（测毕全量还原，
> `grep TRIGFACE src/`=0 亲证）。双侧同语料 hermetic 逐函数（one-mode/`--one`）全量跑，
> 探针事件按 FIRE/gate 聚合。

## ① oracle 触发面全量清单（4 处 setRestartPending(true)）

| # | oracle 位点 | 函数 | 生产调用方 | 触发条件全貌 |
|---|---|---|---|---|
| 1 | heritage.cc:2581 | `Heritage::bumpDeadcodeDelay` | ①`removeRevisitedMarkers`（cc:249，`info->deadremoved>0`）②`heritage()` prev==2 臂（cc:2714-2718）③partial 臂（cc:2723-2730）——后两者门=`!needwarning && deadremoved>0 && !isJumptableRecoveryOn()`（partial 臂另有 isHeritageKnown continue） | bump 内部三重门：空间类型∈{IPTR_PROCESSOR,IPTR_SPACEBASE}→`getDelay()==getDeadcodeDelay()`（无全局 delay）→`!hasDeadcodeDelay(spc)`（override 未装）；过门=insertDeadcodeDelay(+1)+restartPending |
| 2 | jumptable.cc:2703 | `JumpTable::matchModel` | `ActionSwitchNorm::apply`（coreaction.cc:4554） | `jmodel!=0 && tableSize != addresstable.size()` 且 `addresstable.size()==1 && tableSize>1`（流恢复不完整多阶段跳表）→insertMultistageJump+restartPending；否则仅 warning |
| 3 | fspec.cc:5471 | `FuncCallSpecs::deindirect` | `ActionDeindirect::apply` external-ref 臂（coreaction.cc:1236）/constant 臂（cc:1253） | CALLIND→CALL 转换后：callee noreturn/inline/isOverride → 直接 pending；否则 `lateRestriction` 失败 → pending（成功=commit 新入出参零重启） |
| 4 | fspec.cc:5503 | `FuncCallSpecs::forceSet` | `ActionDeindirect::apply` typed-funcptr 臂（coreaction.cc:1269，门=hasTypeRecoveryStarted+PTR→CODE 型+有 prototype+!isInputLocked） | insertProtoOverride 后 `lateRestriction` 失败 → pending（成功=in-place commit） |

## ② 双侧全语料触发计数（FIRE=真正到达 setRestartPending）

| 触发点 | oracle libsqlite3(1385) | Rugra libsqlite3(1385) | oracle sasquatch(810) | Rugra sasquatch(810) |
|---|---|---|---|---|
| **heritage-bump FIRE** | **3**：sqlite3_config(0x949e0)/sqlite3_db_config(0x95350)/sqlite3_test_control(0x96030)，space=stack，delay 1→2 | **3**：同三函数（`--one` 603/608/623），space=Stack，1→2，**逐函数逐参数恒等** | **0** | **0** |
| 重启环执行 | 3（restart-cycle-BEGIN curstart=1，真执行第二遍） | 3 进入（curstart=1）→**无回调降级**（gen 驱动未装 restart_flow） | 0 | 0 |
| jumptable-multistage FIRE | 0（matchmodel-mismatch 0 次） | 0 | 0 | 0 |
| fspec-deindirect FIRE | 0（路径**到达 2 次**=sqlite3_blob_write CALLIND→sqlite3BtreePutData，lateRestriction 均成功不重启） | 0（**路径结构性不可达**，见 ④） | 0（未到达） | 0 |
| fspec-forceset FIRE | 0 | 0（同上不可达） | 0 | 0 |
| heri-partial-gate（中间条件） | 6 | 6 | 6（全部 hknown=1 被 cc:2725 continue 拦下） | 6 |
| heri-prev2-gate（中间条件） | 83 | 49 | 0 | 0 |

prev2-gate 计数差（83 vs 49）**非触发分歧**：oracle 重启真执行→第二遍整管线重跑→heritage 多跑若干 pass→gate 访问多；两侧 FIRE 决策集恒等（3=3，同函数）。sq 面（无重启干扰）中间条件计数也恒等（6=6、0=0）。

**结论：触发面 parity 成立。**PIPESALV 时代前提"oracle 在 sq 语料会触发重启而 Rugra 不触发"**双侧证伪**——sq 面 oracle 同样 0 触发（golden 四类重启文本痕迹亦全 0：Restarted-to-delay/Heritage-AFTER/Second-stage/no-normalized-switch 均未出现）；oracle 真会触发的是 libsqlite3 面，而该面 Rugra 同点同次触发。**缺口不在触发条件，在②（gen 驱动回调接线，重启环已有 pending 但降级）**。

## ③ 第二遍输出效应隔离（oracle 真值，no-restart A/B）

对照构建：同探针树 + `ActionRestartGroup::apply` 在 pending 检出后直接 return（镜像 Rugra gen 面无回调降级形态）。对 3 个触发函数 one-mode 提取输出 vs golden（=真重启形态）：

| 函数 | diff 行 | 第二遍效应形态（with-restart 侧） |
|---|---|---|
| sqlite3_config | 54 | `xunknown8 param_11→uint4`、`xunknown8 *pxStack_b8→uint4 *puStack_b8`（**栈槽去物化+类型精化**）、Heritage 警告位点移动（首 warnvn 变化 0x94eb4→0x94b31） |
| sqlite3_db_config | 16 | **"Heritage AFTER"警告消失**（第二遍 deadremoved 竞争不再发生）；`uint8 uStack_b8` 栈槽→`param_11`（去物化） |
| sqlite3_test_control | 202 | param_5..14 类型精化（int4/uint8）+警告重定位 |

= ②接线后的可观测验收面：libsqlite3 三函数合计 ~272 行应向 golden 收敛，形态=栈槽去物化+类型精化+警告位置（**非 ram 命名**）。golden 侧 db_config 无 Heritage 警告/config 有——由第二遍 needwarning 是否重发决定（db_config 二遍无 gate 事件；config/test_control 二遍 needwarning 重发警告）。

## ④ 结构性缺口（真实存在，非本语料点火）

- **fspec 两触发点生产不可达**：`FuncCallSpecs::deindirect`（fspec.rs:4337）/`force_set`（fspec.rs:4759）函数体忠实，但**全仓零生产调用方**。`ActionDeindirect::apply`（coreaction.rs:12590）是部分重实现：只做 constant 臂的 CALLIND→CALL（且缺 funcptr_align 对齐 cc:1246-1249、用 symbol_table/external_prototypes 查询替 queryFunction、不装 indirectOverride、不跑 lateRestriction/commit、**永不触发 restart**）；external-ref 臂（cc:1233-1240）与 typed-funcptr forceSet 臂（cc:1258-1277）整体缺失。oracle 本语料 deindirect 到达 2 次（均不重启）→当前可观测分歧=CALLIND 转换的 name/override/proto-commit 半边，属 CALLSPEC-0001 族；**若未来语料出现 lateRestriction 失败形态，触发面分歧显形**。登记跟进票（coreaction.rs 域，非本车道写域）。
- ②**gen_decompile/httpd_decompile 回调接线**（PIPE-RESTART-0001 剩余项 a，examples 域）：本测绘给出量化验收面（§③）。
- jumptable 面：`match_model`（jumptable.rs:5122，生产调用 coreaction.rs:3316 镜像 cc:4554）逐句忠实，双语料 0 触发=双侧一致，无缺口。

## ⑤ RAMNAME 族裁决（GEN4-SQ-RAMNAME-0001 状态更新依据）

1. **sq（sasquatch）面**：oracle 0 重启（本测绘全量）→"oracle restart→reset 子 Action→mapglobals 二遍建符号"机制假设对该面**不成立**；Rugra sq ram0x 594 残差与重启无关，应按 SQ-STACKSPILL 残差移交 (1) 的方向归因（**CSPEC-GLOBAL-APPLY-0001**：gen 裸面全局 scope ranges 缺失→ram varnode 无 addrtied 符号——canon 驱动手补 add_range 故不受影响）。
2. **libsqlite3 面**：oracle 真重启，但 Rugra 镜像（gen5 存档）129 个 ram0x **分散于 ~40 函数**（sqlite3_vsnprintf/snprintf/log/str_appendf…），3 个重启函数 ram0x=**0**——重启自愈预测的"残差聚集于重启函数"形态双侧皆无。ram0x 族与重启正交。
3. 第二遍真实效应（§③）=栈槽/类型/警告域，**非命名域**。

## ⑥ 本车道修复

`remove_revisited_markers` 空间来源改为调用方传入的段空间（`memrange.space`），镜像
`getInfo(addr.getSpace())`（heritage.cc:247）——原实现取 `remove[0]` 的空间+空表回退
Register，在 oracle 不可达输入（跨空间 remove/空表）上会选错 HeritageInfo。oracle 的
`!removevars.empty()` 守卫（cc:2626）+collect 单空间窗口使两侧恒等，故为保真形式修正，
canon curl/httpd A/B **字节恒等**亲证零行为变化。

## ⑦ 复现配方

```bash
# oracle 探针构建+全量（/dev/shm/rugra-tests/trigface/，内存盘易失）
python3 build_probe_oracle.py                # 锁定树提取+7 组探针+构建
python3 run_probe_corpus.py /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 --out oracle_sqlite_full.json
python3 run_probe_corpus.py /usr/local/bin/sasquatch --out oracle_sq_full.json
# no-restart 对照（第二遍效应隔离）
python3 extract_one_mode.py oracle-norestart/golden_dump_norestart <bin> 603,608,623 norestart_out
# Rugra 探针（临时 eprintln 后）
python3 run_probe_rugra.py <bin> --out rugra_<corpus>_full.json
```
