# Lane EQ3 (sb-cm3) — 停车链×master 终局测试合并 Round 3 终报（双优达成）

- 日期: 2026-09-24 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/cm3, branch **wt/cm3**
- **merge commit: 54fa3f82de3f91e6eb0d4a542fdeb57ddabaf8d2**（parents = 8ed539e3 × 9e2524c5, merge-base 983e0fc9）
  - side A = master **8ed539e3**（任务锁定基线;EX2/FE/EM3/FC/FB/FA2/FD/EZ/ER/ET/ES/EP/EI/EI2/FJ/FH 等 lane）
  - side B = chain tip **wt/concatram@9e2524c5**（DL RC1/RC2 + DP RC3 + EC + EH 1c7bde2b + EY2 f8ee7548 + FF 9e2524c5）
- oracle: Ghidra 12.0.4 e40ed130; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-cm3（master 基线探针 sb-cm3-master）
- 写域: 仅本 scratch worktree + /dev/shm/rugra-tests/sb-cm3/。**未动 master,未做 master 合并——终裁归 root**。
- hook/门禁自检: gate health OK、annotations 97/97、refs --strict OK、doc-sync 7/7、commit message 红词零命中。

## 0. 双优判定（一句话）

**达成**：curl **2147/0/0** < master 2152/0/0 < chain 2507/0/0；httpd **2153/0/0** < master 2225/0/0 < chain 2250/0/0。
合并态对**两条基线同时占优**、defects/numbering 双零、双跑字节恒等、三投影 MATCH×3、emitter main 秒级完成
（EW 死锁修复在合并态有效,round-2 的 stage-emitter 挂起已消除）。合并预期区间 httpd ~2200-2230 / curl ≤2152
**双双被超越**。

## 1. 冲突清单与解决（实际与预期的差异）

git merge --no-ff 报 5 个文本冲突;**coreaction.rs 与 fspec.rs 预期冲突实际零冲突 auto-merge**
（master 侧自 983e0fc9 起对 coreaction 的新增全部落在链未触碰的函数区,fspec master 零改动）:

| 文件 | 冲突实质 | 解决 |
|---|---|---|
| examples/httpd_decompile.rs | master 把 init 尾重构为 `(arch, default_effects)` 返回（ES 效应面,defaultfp 捕获后清空）vs 链 RC2 保持 `Ok(arch)`（defaultfp 绑定） | **四层共存**: RC2 完整 init 链（register_xref/archid/commentdb/TypeFactory/共享 store parse_compiler_config,**defaultfp 保持绑定=链 2250 亲测配置**）+ ES 效应表（defaultfp.effectlist 捕获 → `fd.funcp.effects` 注入;`try_has_effect` 显式表优先、否则回退同源模型记录,两面同答案）+ EX2 LAB 层（branch_ref_addrs→code_labels,auto-merge 区）+ master SpecQuery::unique_inject_base。auto-merge 残留的 `cspec_store` 未定义引用修正为共享 `store`;**删除 `arch.defaultfp = None`**（master-only 世界的 2634 测量不适用于链世界,见 §4 归因①）。另删除双侧重复的 SleighSymbolLookup impl（E0119） |
| src/disasm/x86_64.rs | **未报冲突但语义冲突（本次最重要的人工干预）**: master EP lane 加 `segment` 字段 + x86_lift `apply_segment` 外包 INT_ADD(FS_OFFSET,EA);链 FF lane 在 extract_operands 里 base=None+FS/GS 前缀时合成 `base="fs_offset"`——两者叠加 = `INT_ADD(FS_OFFSET, INT_ADD(fs_offset,d))` 双重包裹 | **取 master 机制为唯一通道**,删除链的 base 合成 fallback。单一 wrap 打出与 FF 目标完全相同的 `*(in_FS_OFFSET + 0x28)` 形,且额外覆盖 `[fs:reg+idx*scale+disp]`（链方案 base=None 才触发、覆盖不全）。EP 的 LIFT-FS-CANARY-FORM-0001 单测在新形态下原样通过 |
| src/disasm/x86_lift.rs | get_register 的 fs_offset/gs_offset 注释双侧各写一版（映射本体相同 0x110/0x118） | 注释合并（双侧 probe 出处都保留） |
| docs/TODO_BOARD.md | 2 处: ER/FJ DONE 行 vs 链侧 SUBRIGHT 旧行 + EY2 三行;DP/EW 行 master 已闭 vs 链侧旧 open 行 | 行级并集: master 新行（ER DONE/FJ DONE/EW 闭环）+ 链 EY2 三行（FSPARM-SYMINSTALL/LEGACY-BYPASS/INRAXRSP-RESIDUAL,清掉被污染的行尾）;链侧过期 open 行按 master DONE 行去重 |
| docs/api/coreaction.md, docs/api/ruleaction.md | 双侧同日新增日志条目 | 条目并集（无重复标题,已核） |

### auto-merge 语义安全核验（逐 hunk,非仅零冲突）

- **src/coreaction.rs**: master 新增 11 hunk 全部落在 ActionUnreachable/SwitchNorm/MarkExplicit/MarkImplied/SetCasts(castInput let-binding=EW 修复)/StructureTransform/ReturnSplit/tests;链侧区域 ActionConstbase/InputPrototype/ParamDouble/StackSolver/StackPtrFlow/ExtraPopSetup——**函数级零重叠**。EW 修复（prev_cast_input let 绑定）在链内容之上正确就位。
- **src/funcdata.rs**: master 唯一 hunk @7391（ES prelude 效应尾）vs 链 @10467-10561（EH adjust_input_varnodes）——零重叠。
- **src/ruleaction.rs**: master 新增（EZ meld/FC AndCommute/FB/FE 等,链文件坐标 4588-12781 + 17952-18463 + tests）避开链侧 17192-17309 区域。
- **src/printc.rs**: master 独占（EX2 labels 等 +148）;链零改动。
- **src/fspec.rs / src/prettyprint.rs / src/varmap.rs**: `git diff wt/concatram` 为空 = **合并态与链逐字节相同**（master 自 merge-base 未触碰）。
- **src/disasm/x86_lift.rs**: master hunks 全部为 segment 字段机械传递 + 常量折叠 segment 门控（@@ -3896 的 rip-folding 加 `segment.is_none()`）;链 FF 的 lea 臂（Const 空间绝对地址+zext）/mov 32 位 zext 臂未被触碰,原样在位。

## 2. 合并态三门禁（default 模式,fast-release,双跑字节恒等）

| 门禁 | 合并态 54fa3f82 | master 8ed539e3（本 lane git archive 亲测） | chain 9e2524c5（sb-concatram 归档） | 判定 |
|---|---|---|---|---|
| curl E2E canon | **2147/0/0**（124/124 fn,35s） | 2152/0/0 | 2507/0/0 | **双优 + defects/numbering 0** |
| httpd E2E canon | **2153/0/0**（29/29 fn,3.8s,main 完成） | 2225/0/0 | 2250/0/0 | **双优 + defects/numbering 0** |
| gcc 审计 | curl 82OK/25FAIL（==master）;httpd 失败集 ≡ 链（master 多 2 OK,见 §4-⑤） | 82/25 | 82/25（httpd 7/22 CLI 口径） | 无缺陷级新增 |
| 三投影（RUGRA_MIRROR=1 全家,producer=54fa3f82） | next_url / match_url / parseconfig.constprop.0 **MATCH×3**（非 META diff=0） | — | — | ✅ |
| httpd main emitter 模式（RUGRA_STAGE_PROJ） | **3.3s 完成,294 @BEGIN,67.6MB 完整投影** | 4.4-6.7s（历史） | round2 合并态 >600s 死锁 | **EW 修复在合并态有效,round-2 挂起消除** |
| cargo test --lib 串行 | 1682P/18F,失败集=已知预存家族逐名同集（funcdata 17+heritage 1） | 同族 | 1658P/18F 同族 | ✅ 零回归 |

## 3. 逐函数 delta（golden 口径;双侧基线均本 lane 亲测/归档复算）

### httpd（total: master 2225 → merged 2153 = −72;chain 2250 → merged = −97）

vs master 仅 2 函数落后,19 函数改善;vs chain 4 函数小幅落后,10 函数改善:

| 函数 | master | chain | merged | vs_m | vs_c | 备注 |
|---|---:|---:|---:|---:|---:|---|
| main | 657 | 800 | 761 | **+104** | −39 | 见 §4-① |
| ap_fini_vhost_config | 366 | 312 | 352 | −14 | +40 | 见 §4-② |
| ap_pregsub | 211 | 170 | 161 | −50 | −9 | 双侧占优 |
| ap_update_vhost_from_headers | 168 | 169 | 153 | −15 | −16 | 双侧占优 |
| ap_getparents | 116 | 125 | 111 | −5 | −14 | 双侧占优 |
| ap_ht_time | 69 | 70 | 54 | −15 | −16 | 双侧占优 |
| ap_strcasecmp_match | 63 | 66 | 52 | −11 | −14 | 双侧占优 |
| ap_vhost_iterate_given_conn | 37 | 46 | 48 | **+11** | +2 | §4-③ |
| ap_update_vhost_given_ip | 57 | 46 | 46 | −11 | 0 | |
| ap_strcasestr | 48 | 60 | 42 | −6 | −18 | 双侧占优 |
| ap_strcmp_match | 42 | 46 | 40 | −2 | −6 | |
| ap_parse_vhost_addrs | 48 | 50 | 46 | −2 | −4 | |
| ap_getword / ap_make_dirstr_prefix | 44/44 | 36/35 | 36/35 | −8/−9 | 0/0 | 取链值 |
| ap_field_noparam | 33 | 31 | 31 | −2 | 0 | |
| ap_os_is_path_absolute | 29 | 30 | 29 | 0 | −1 | |
| ap_no2slash | 30 | 22 | 23 | −7 | +1 | §4-④ |
| ap_make_dirstr_parent / ap_matches_request_vhost / ap_count_dirs | 22/25/21 | 22/21/18 | 22/21/18 | 0/−4/−3 | 0/0/0 | |
| ap_stripprefix | 25 | 20 | 15 | −10 | −5 | 双侧占优 |
| ap_init_vhost_config / ap_pregcomp | 16/15 | 14/13 | 14/13 | −2/−2 | 0/0 | |
| ap_is_matchexp | 16 | 9 | 11 | −5 | +2 | §4-④ |
| ap_set_name_virtual_host / ap_getword_nc / suck_in_APR / ap_get_server_built / ap_pregfree | 5/4/4/4/6 | 5/4/4/4/2 | 5/4/4/4/2 | 0/0/0/0/−4 | 0/0/0/0/0 | |

### curl（total: master 2152 → merged 2147 = −5;chain 2507 → merged = −360）

**vs master 零回退**: 全部 124 函数 delta ≤0,其中 3 函数改善——`__libc_csu_init` −3、`glob_word` −1、
`_start` −1（master 残留的 `in_RDX/in_RSI/in_EDI` 裸寄存器声明被链的参数定型吸收成 typed 参数,glob_word
少 1 条 legacy 死声明=EY2 交付面）。vs chain = master 的 12 函数改善全部继承（getparameter −197、
main −84、parseconfig −16、my_get_line −14、next_url −11、glob_set −9、myprogress −6、
file2string/glob_range −6、match_url −4、my_get_token −3）,零回退。

## 4. 异常逐个归因登记

1. **httpd main vs master +104（唯一显著回退）**: master main 骨架仅 175 行（不完整体,其 657 diff 大半是
   缺失内容）;merged main 355 行,对 master 为**纯超集（+338/−0）**——链世界（RC1 push 模板+RC2 cspec+
   RC3 extrapop+EH 参数族+FF lifter 修复）把 main 体物化完整,该域即 EQ round-1/EV 已判决的
   GOLDEN-CONTRACT-PUSHABSORB-0001 + EV §3.1 族谱（过度物化栈写/CONCAT/RAM 裸全局,FF 后已大幅收敛
   884→800→merged 761）。−39 vs chain = master 的 LAB/goto/cover 改善在链形态上叠加生效。
   **非合并伪影,为链内容与 master main 世界观的真实 tradeoff**（选链形态则 main 完整但骨架大,
   选 master 形态则 main 短小但缺体;合并态总账与除 main 外全部函数均优）。
2. **ap_fini_vhost_config vs chain +40 / vs master −14**: 合并态携带链世界 raw-param 族
   （in_ 寄存器 13、in_RIP 10、extraout 8——BOOMATTR residual ①/CHAINMERGE-INRIP-PRINTFAMILY-0001/
   CHAINFIX-INRAXRSP-RESIDUAL-0001 已登记域）+ master EX2 LAB 层在链形态体上新增 label/goto 标记
   （merged 9 vs chain 4）。两基线之间取中,已知开放域,无新族。
3. **ap_vhost_iterate_given_conn vs master +11**: EQ round-1 已登记"三向各有形态差,非单调劣化"
   （raw-param 命名族）;本轮 master 22 行/链 31/merged 33,延续同域。
4. **ap_no2slash +1 / ap_is_matchexp +2 vs chain**: 拼写级形差（in_ 记号 2 处 vs master label 1 处互换等）,
   无缺陷。
5. **gcc 审计 httpd: master 10 OK/直接口径 vs merged 8（≡ chain 8）**: `ap_os_is_path_absolute`/
   `ap_pregcomp` 在链世界因 typed 拼写（int8/uint8/in_register 名,EV §4 已判族,golden 亦用非标准 C 拼写）
   无法独立编译——非缺陷级,与链逐函数完全一致,无合并新增。
6. **defaultfp 绑定决策（合并裁决心迹）**: master ES 形态在 master-only 世界测得 defaultfp 绑定=2634 劣化,
   故清空;链世界 defaultfp 绑定=2250 亲测（RC2 起即绑定）。合并态选**绑定+效应表双面**（try_has_effect
   显式表与模型记录同源同答案,无冲突）。若 root 想复现 master-only 形态的 main 数字,可在合并态上单测
   `arch.defaultfp = None` 一行的差分——非本 lane 裁决域。
7. **FS/GS 双机制冲突（本次新发现的合并伪影,已修）**: 见 §1 x86_64.rs 行——若不删除链的 base 合成,
   合并态会产生双重 INT_ADD 包裹。已修并有 EP 单测锁定;curl 路径（SLEIGH 主路径）本就零影响,
   httpd FS canary 形态与 FF 交付逐字相同。

## 5. root 终裁输入（建议）

1. **建议并入 master**: 双优判定成立（curl −5/−360、httpd −72/−97,双零,确定性,三投影 MATCH,
   emitter 挂起解除）。round-2 的两大保留意见（GOLDEN-CONTRACT 裁决前骨架差无法定性 + stage-emitter
   死锁）中,后者已随 EW 修复在合并态消除;前者的残余面=main +104/ap_fini +40（§4-①②）,全部落在
   EV 已判族谱内,量级较 round-2（+314）收窄 77%。
2. 合并态比 EQ round-2 预期显著更优的原因（供 root 复核置信度）: master 侧 EX2/FE/EM3/FC 的标签/goto/
   cover 改善与链侧 RC1-3/EH/EY2/FF 的物化/参数/lifter 改善**作用面几乎不相交**,叠加近乎线性;
   FS/GS 双机制是唯一发现的真交互,已修复。
3. 遗留: main/ap_fini 残余族（EV ①-⑥ 修域清单不变）;curl 侧无任何遗留。
4. **master 已前进提示（2026-09-24 本 lane 收尾时发现）**: master tip 现为 d09fa30f
   （= 8ed539e3 + FL lane bc22461d〔x86_lift 分支目标改 1 字节 code-ref〕+ FI lane 2 个
   docs commit）。`git merge-tree` 模拟 54fa3f82 × d09fa30f = **0 文本冲突**（FL 的
   cbr/cmovcc/jmp 臂与本次 segment/lea/mov 臂不同区）;但 FL 与链内容同为 lifter 行为改动,
   root 终裁并入后建议按惯例重跑双语素门禁确认叠加态（预期 FL 的 1 字节 code-ref 修复
   HTTPD-FULLEMPTY-ELSE-0001 与本合并无交互,未经亲测）。

## 6. 产物（/dev/shm/rugra-tests/sb-cm3/）

- curl_merged.c / curl_merged2.c（cmp 恒等）、httpd_merged.c / httpd_merged2.c（cmp 恒等）
- master_curl.c / master_httpd.c + *.stderr（8ed539e3 git archive 亲测基线,复现 2152/2225）
- httpd_gold_{merged,chain,master}.txt / curl_gold_{merged,chain,master}.txt（逐函数 golden-diff 底表）
- perfn_delta.py（双侧逐函数对称 diff 工具,复用 compare_ghidra 归一化）
- cm3.{next_url,match_url,parseconfig}.projection（pre-commit）+ final.{...}.projection（producer=54fa3f82）
- cm3.httpdmain.projection（emitter 模式,67.6MB 完整）+ *.err
- audit_sets.txt（三树 gcc 审计逐函数集合对比）、test_summary.txt / test_failures.txt
- commit_msg.txt（红词零命中）;master-src/（基线探针源,root 集成后回收）
- target: /dev/shm/rugra-targets/sb-cm3 与 sb-cm3-master（root 集成后回收）
