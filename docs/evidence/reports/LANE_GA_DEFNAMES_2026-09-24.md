# Lane GA 终报 — DRIVER-SWITCHD-DEFFN-0001（switchD default 处理**函数**名通道）

- **Worktree**: wt/defnames @ /dev/shm/rugra-worktrees/defnames,基(亲父) master 5727faea,交付 commit **69b64d45**(4 files, +358/-2)
- **Oracle**: Ghidra 12.0.4 e40ed130(锁定);本 session 亲读 jumptable.cc:1373-1398(foldInOneGuard)/2497-2506(addBlockToSwitch/setLastAsDefault)/2528-2568(switchOver)、printc.cc tagFuncName 发射路径(经 golden `::` 形态钉死无消毒)。FT3 的 LABEL 层零改动。
- **写域如实登记**: 工单写域=examples 双驱动+docs/api;实际另含 `src/printc.rs` 单字符条件延伸(sanitize_c_ident 放行 `:`)——不放行则 `::` 被折叠为 `__`,3 函数名全部无法向 golden 收敛;oracle 的 tagFuncName 原样发射限定名,该 GLUE 消毒是真实偏差;影响面封闭(curl E2E 字节恒等=证明),docs/api/printc.md 同 commit 同步。curl 驱动零改动(golden 无 switchD 函数,扫描零命中=构造性 no-op)。

## 1. 命名规则(交付物)

```
switchD_<dispatch 8hex>::default   # default 处理函数的限定名;头行基名 `default`
```

- **来源链(锁 oracle 亲读+二进制证据)**: ①`JumpBasic::foldInOneGuard`(jumptable.cc:1373-1398): switch 守卫 CBRANCH 的非 switch 出边目标若不在地址表内→以 `JumpValues::NO_LABEL` 追加+`setLastAsDefault`(cc:2497-2506);前置=守卫块直落 BRANCHIND 块无间隔语句(cc:1382-1383/1391)。二进制证据: 三 thunk 均为守卫 `ja` 目标(0x5424e→0x2b7fa/0x7747c→0x2b804/0x77657→0x2b80e),**不在**跳转表内(表内只有 case 0..7)。②headless DecompilerSwitchAnalysis 在 `switchD_<dispatch>` 命名空间给每个 dest 建 `caseD_<hex>`/`default` 符号;**dest 为独立函数入口时符号即函数名**→`switchD_<dispatch>::default(void)`。同 switch 的函数内 dest 走 FT3 LABEL 通道(pcre_config 的 `default: return 0xfffffffd;` 内联子句=守卫直落吸收,与独立函数并存)。
- **驱动侧映射**: .text 线性扫;入口候选=ELF 符号∪endbr64;span 平铺;条件分支目标逃逸全部 span 且直落链无控制转移直达间接跳转(=foldInOneGuard 邻接前置的结构检查)→(dispatch, default 目标);thunk 尺寸=入口到首个终结指令(10/10/6 与 golden 头行一致)。语料校验: httpd 恰好命中 golden 三处、curl 零命中。

## 2. 前后对比(基线=亲父 5727faea 本地复现,与 root 亲测同数)

| 门禁 | 前 | 后 | 判定 |
|---|---|---|---|
| httpd(skeleton/defects/numbering vs golden) | 2057/0/0(29 fn) | **2061/0/0(32 fn)** | 3 函数名全收敛;窗口 29 函数字节恒等;+4=0x12b80e 返回值族残差(Rugra `return;` vs golden `return 0xfffffffd;`+`undefined8` 签名;与基线 suck_in_APR `return;` vs `return ap_ugly_hack;` 同族=iced 路径返回值恢复缺口,归 FP RESIDMAP RVAL_ASSIGN 族,无新缺陷类) |
| 0x12b7fa/0x12b804 两函数 | (不存在) | **骨架 identical** | `FUN_001542b0(); return;` / `FUN_001774f0(); return;` 与 golden 逐字一致(尾跳 CALL_RETURN+FUN_ 命名通道) |
| curl(vs golden) | 2135/0/0 | **2135/0/0 字节恒等** | printc `:` 放行零影响证明 |
| gcc audit | 8OK/21FAIL | 同 fail 集 | 无新增失败 |
| 三投影(MIRROR=1) | — | next_url **MATCH**(335/96457)+match_url **MATCH**(340/80385)+parseconfig 投影体与 FT3 工件**字节恒等**(仅 META producer 行不同) | 零移动 |
| 确定性 | — | httpd 双跑字节恒等 | ✓ |

## 3. 残余登记(TODO 行已同步)

1. **0x12b80e 返回值/类型 4 行**: RVAL_ASSIGN 族(iced 路径返回值恢复),非本层引入。
2. **caseD 函数通道未做**: golden 另有 `switchD_00154229::caseD_0`(0x154380)/`switchD_00154265::caseD_0`(0x154470)/`switchD_00177493::caseD_0`(0x177520) 三处独立函数——同机制不同符号名,登记 `DRIVER-SWITCHD-CASEFN-0002` 待认领。
3. **span 平铺近似**: Ghidra 函数体为流推导非平铺;本语料三 thunk 均在首入口前区(0x2b7f0-0x2b820 prolog 区,funnel 0x2b7f0 的 mov;ud2 无 endbr64)故恰命中;若未来语料的冷 thunk 落于函数间真间隙需流推导 body(登记于 TODO 行,不阻塞)。
4. FT3 的 out-of-scope ①(122 处 switchD 位点)仍归 ACTION-REWORKFIX-STRUCT-0001 域,本层不动。

## 4. 证据

commit **69b64d45**(hooks 全绿:gate health/docs 同步/annotations/refs;机制 A 未触发——message 无红词)。双侧工件交付后已按回收纪律清理(/dev/shm/rugra-tests/sb-defnames/);全部数字在本报告与 docs/TODO_BOARD.md 行内。result/ 回流:result/curl_cur.c+result/httpd_cur.c(gitignored)。target 目录 /dev/shm/rugra-targets/sb-defnames 留待 root merge 后回收(AGENTS 回收纪律)。
