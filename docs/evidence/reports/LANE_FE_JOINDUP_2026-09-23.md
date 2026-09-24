# Lane FE (joindup): PRINTC-LABEL-WITHOUT-GOTO-0001 根因闭环 — joined_/dup_ 形态族

Commit: **a0c272e5** (wt/joindup, 基 master 2a32802e = EX2 亲父)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c
写域实际落点: `src/printc.rs`(emit_block_goto 目标解析 14 行) + `docs/api/printc.md` + `docs/TODO_BOARD.md`
(**blockaction.rs 未动** — 根因不在 flag 生命周期,printc=机制 B 域,无需机制 C Cross-Review)

## ① joined/dup 机制缺口一句话
**f_joined/f_duplicate 旗标链自始完整(node_join_create_block funcdata_block.cc:785 置位→bblocks 存活→print 快照→emitLabel cc:3184-3187 判定全通);真缺口=emit_block_goto 的 goto 目标地址读 legacy 类型化投影 `BlockGoto::goto_target`(恒 None)→addr=0→零地址防御吞掉全部结构树 goto 语句,只剩 label 孤立输出。修复=切 `target_dyn`(Ghidra gototarget 活体捕获 block.hh:548)+`flow_entry_address`(emitLabel getFrontLeaf→subBlock(0)→getEntryAddr 链 printc.cc:3167-3170)。**

EX2 归因勘误(已记 TODO):①"blockaction flag 生命周期域"不成立;②"httpd −32 残差=joined 族"不成立——golden 122 处 joined 全在 Rugra 29 函数语料之外,该差值实为 goto 结构差+其他 skeleton 族。

## ② 前后数字(基线=亲父 2a32802e 亲测)
| 门禁 | 基线 | 交付 | Δ |
|---|---|---|---|
| curl (124 fn) | 2381 / 0 / 0 | **2330 / 0 / 0** | **−51** |
| httpd (29 fn) | 2238 / 0 / 0 | **2224 / 0 / 0** | **−14** |
| 三投影 (RUGRA_MIRROR=1 全家) | MATCH×3 | **MATCH×3** | next_url(335 stages/96457 ops)/match_url(340/80385)/parseconfig.cp0(335/130099) vs sb-ord191/sb-parseconfig 钉板 |

- **label-without-goto 位点归零**(curl 0 / httpd 0);curl my_get_token `goto joined_r0x001037b2;`+label 双行=golden 同形(EX2 witness 收口)。
- **joined_ 形态族在对比域内收敛**:curl 唯一 joined 对已齐;httpd golden joined 全在语料外(非对比域)。
- 新暴露正确 goto:witness ap_fini_vhost_config `goto LAB_0012d2c0;` = golden 同位同形。
- 逐函数改善:curl main −31/getparameter −15/my_get_token −1/parseconfig −1/glob_range −2/next_url −2;httpd main −11/ap_ht_time −5/ap_getparents −2。
- 逐函数残差 +1 ×5(暴露位,分类见 ③):curl glob_set;httpd ap_parse_vhost_addrs/ap_fini_vhost_config/ap_pregsub/ap_no2slash。
- printc 单测 12/12;gcc 审计 curl 82OK/25FAIL、httpd 6OK/23FAIL 均等于基线;cargo test --lib 全量三跑 1674/19、1673/20、1675/18 —— 失败集全部落在预存 flaky 家族(funcdata alignment/ssa 18 + heritage::test_heritage_creation 1,与 SB-ORD159 记录的同树摆动形态一致),printc 域零失败。

## ③ 残差移交(登记 PRINTC-GOTOSTRUCT-RESID-0001,blockaction 域)
addr=0 blanket 抑制曾掩盖结构器树形差;修复后 5 处结构族 goto 现形(golden 以循环回边结构化,Rugra 终态树为 BlockGoto):curl glob_set 0x104c20;httpd 0x12cfcb/0x12e475/0x12e87b;另 glob_set 0x104c5e 为拼写族(golden=switchD_00104c45_caseD_5e 同地址异名)。标号 token 残差:curl 9/7、httpd 17/54(主族=switchD_caseD 命名+5+5/5+5 地址错配)。

## ④ 回收
- 证据保留 /dev/shm/rugra-tests/sb-joindup/(curl/httpd base+final 双门禁日志、三投影 m_*.projection、perfunc txt、commit_msg.txt)。
- result/curl_cur.c + result/httpd_cur.c 已回流(gitignored)。
- /dev/shm/rugra-targets/sb-joindup(CARGO_TARGET_DIR)保留至 root 集成合并后回收。
- 探针(RUGRA_JOINDUMP 树 dumper + GOTOPRINTS probe)已全部从源码移除,commit 干净(3 files, +47/−5)。

## ⑤ 复核请求
printc.rs=机制 B 白名单(差分门禁已过:defects=0/numbering=0,## Differential 块在 commit message)。**blockaction.rs 未改动——机制 C 声明域为空,无需 Cross-Review**;root 快速复核即可(单函数 14 行,emit_block_goto target_dyn+flow_entry_address 切换,四类语义 Evidence 块在 commit)。
