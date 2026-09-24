# Lane EX2 (labspell 续跑): PRINTC-LABSPELL-LABSYMS-0001 交付报告

Commit: **739cb275** (wt/labspell, base bfa9eabf)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c
写域实际落点: `src/printc.rs`(emitLabel 三臂 + code_labels 层) + `examples/curl_decompile.rs` + `examples/httpd_decompile.rs`(反汇编流引用参考集安装) + `docs/api/printc.md` + `docs/TODO_BOARD.md`

## ① 前代(EX)进展盘点
- src/printc.rs: emitLabel 三臂已落(code_labels/code_label_base/joined/dup 投影 + set_code_label_layer),未验证即配额中断。
- 驱动: pcode 级 BRANCH/CBRANCH 常量目的地扫描版 LAB_ 注入(curl+httpd),fix3 实测 curl 2394 / httpd 2251。

## ② 归因补完(命名规则缺口一句话)
**golden 的 `LAB_%08x` 前缀 = 前端 DB 在每个"直接分支(jmp/jcc)静态目标"地址上的默认 LABEL 符号,emitLabel cc:3173-3181 queryCodeLabel 命中即整名替换;Rugra 无该符号数据恒走 cc:3183-3192 泛型 `code_r0x` 臂。**

## ③ EX2 关键修正(前代方案的结构性缺陷)
pcode 级扫描恒丢目标: 管线阶段(condexe 合并/块手术)把 CBRANCH 目的地输入改写为 **unique 空间临时量**(实证 ap_fini_vhost_config blk 0x2d0a2: 块图 outs=[0x2d175,0x2d0f0] 而 CBRANCH in(0)=(Unique,0x10000114))。改用**反汇编流引用集**(is_branch() && branch_target())= 前端建 LAB_ 符号的同一 reference 机制,与 pcode 状态解耦。另一坑: `is_constant()` 查 varnode flag 而 lifter 的 const 目的地只标 space=Const 无 flag → 前代过滤漏检(已随 pcode 扫描一并退役)。

## ④ 三门禁(EX2 亲测,基线=亲父 bfa9eabf: curl 2511/0/0 + httpd 2282/0/0)
| 门禁 | 基线 | 交付 | Δ |
|---|---|---|---|
| curl (124 函数) | 2511 / 0 / 0 | **2381 / 0 / 0** | **−130**(DY 潜力 −128,超额) |
| httpd (29 函数) | 2282 / 0 / 0 | **2238 / 0 / 0** | −44(DY 潜力 −76) |
| 三投影 (RUGRA_MIRROR=1 全家) | MATCH×3 | **MATCH×3** | next_url/match_url vs sb-ord191 钉板,parseconfig.constprop.0 vs sb-parseconfig 钉板(stage_bisect v1.2) |

- 共享地址拼写错配归零(curl 2→0、httpd 4→0);逐函数零回退(curl 10 函数改善: main −39/getparameter −50/parseconfig −15/next_url −9/match_url −4/myprogress −2/my_get_token −2/my_get_line −4/glob_set −4/glob_range −1/int −18;httpd 7 函数: ap_getparents −13/ap_ht_time −9/ap_fini_vhost_config −6/ap_update_vhost_from_headers −6/ap_strcmp_match −4/ap_strcasecmp_match −2/ap_pregsub −4)。
- printc 单测 12/12;gcc 审计 curl 82OK/25FAIL == DY 基线。

## ⑤ 未决(全部非本写域,已登记/移交)
- **joined_/dup_ 形态**(curl 0x1037b2 joined_r、httpd golden joined 122 occ): blockaction BlockCopy 链 flag 生命周期 → PRINTC-LABEL-WITHOUT-GOTO-0001 同域。
- **rugra-only/golden-only 标号地址**(curl 5+5、httpd 5+5): goto 目标结构差(块分裂点不同/结构器未发射块),非拼写层。
- httpd −44 vs 潜力 −76 的差值 = 上述两族(结构差地址 + joined)。

## ⑥ 回收
- 工件结论归档本报告;`/dev/shm/rugra-tests/sb-labspell/` 保留 fix5 双门禁日志 + bisect×3 + compare_labels.py(复核用),dbg/ 探针目录已清。
- `result/curl_cur.c` + `result/httpd_cur.c` 已回流(gitignored)。
- `/dev/shm/rugra-targets/sb-labspell`(CARGO_TARGET_DIR)保留至 root 集成合并后回收。
