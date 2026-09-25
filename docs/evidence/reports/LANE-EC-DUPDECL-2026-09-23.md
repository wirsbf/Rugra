# Lane EC — VARMAP-DUPDECL-EXTRAOUT-0001（DP 停车链 numbering 阻塞清零）交付报告

- 分支: wt/dupdecl（worktree /dev/shm/rugra-worktrees/dupdecl，基 wt/sb-pushabsorb@764c3036 = DL RC1+RC2+RC3 合流态）
- Oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b（x86:LE:64:default / gcc cspec）
- 构建口径: fast-release 迭代 + release 验收；CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-dupdecl（已回收）
- 交付 commit: **ea71b739**（3 files: src/prettyprint.rs + docs/api/prettyprint.md + docs/TODO_BOARD.md）

## 1. numbering 16 处形态清单（基线实测，compare_ghidra.py --mode numbering）

| 函数 | 数量 | 重复声明名 |
|---|---|---|
| ap_parse_vhost_addrs | 7 | bVar22, bVar23, pcVar15, uVar10, uVar16, uVar24, uVar9 |
| ap_set_name_virtual_host | 6 | bVar18, bVar19, uVar10, uVar14, uVar20, uVar9 |
| ap_update_vhost_from_headers | 3 | iVar7, uVar12, uVar6 |

全部为 "duplicate: X declared twice"（同名双/三声明，类型互异 long↔uint8↔int/bool↔int）。

## 2. 根因一句话

**根因不在 varmap**（ScopeLocal 每名字恰一符号、printc 作用域遍历每符号恰发射一次——38 符号 dump + 逐符号类型比对证明清白）；16 处重复声明全部由 prettyprint.rs 两个无 oracle 对应物的 GLUE 文本 pass 制造：printc 按 Symbol dtype 逐字发射的带括号声明形（`undefined1 (*pauVar7)[16];` / `void (*pVar4)();`，与 oracle direct-runner golden 同形）含 `(`，使 ①`has_symbol_driven_decls`（flush 旁路判据）与 ②`backfill_missing_locals` 的 declared 收集在声明块中部提前 break——①→flush 注入半臂运行，type_ok 表不识 uint8/uint/uint1 拼写，注入 `int uVarN;`（9 处）；②→其后全部已声明名按"缺失"整组重注入（覆盖全部 16 处；对照实验：单独旁路 backfill 即归零、单独旁路 flush 剩 9）。

## 3. 修复（跨租约最小化，root 裁准；printc.rs 未动，varmap 域零改动）

1. 新增 `has_symbol_driven_decls_walk_parens()`：同 acceptance 集（`;` 结尾、无 return、无 `=`）但带括号纯声明行 continue 而非 break；**仅**接入 flush_func_remove_unused 旁路（`||` 并联）。P22 掩码（symbol_driven_function_line_mask）**刻意**保持原判据——放宽会新增旁路、丢 curl progressbarinit 的 `*param_N` legacy 合法性修复（实测 `char *param_1`→`long param_1` 翻转、curl E2E 字节漂移；该 fiction 真解在 FuncProto 参数指针定型域另案）。
2. `backfill_missing_locals` declared 收集新增带括号纯声明分支：抽 `(*pauVar7)`→pauVar7，continue；真 body 语句（含 `=`）照旧拒绝。

## 4. 门禁数字（release+fast-release 双口径，RUGRA_MIRROR）

| 门禁 | 基线 764c3036 | 交付 ea71b739 |
|---|---|---|
| httpd skeleton/defects/numbering | 2137/0/**16** | **2104/0/0** |
| ap_parse_vhost_addrs | 326/0/7 | 311/0/0 |
| ap_set_name_virtual_host | 228/0/6 | 217/0/0 |
| ap_update_vhost_from_headers | 219/0/3 | 212/0/0 |
| curl（vs 4073 基） | 4073/0/0 | **逐字节相同**（cmp 零差异） |
| --func main | TIMEOUT（HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001） | 不变（两态同） |
| gcc 审计 | httpd 1/27, curl 101/19 | 不变 |
| cargo test --lib（串行 prettyprint/varmap/printc） | — | 63/63 |
| cargo test --lib 全量（串行） | 1650/18（基预存 funcdata/heritage 残差） | 1650/18 同集 |

skeleton -33 = 恰为被注入的重复声明行消亡；剩余 skeleton 为预存（call-args/switch-body 族，他 lane 域）。

## 5. 移交/残差

- ①裸 `unique0x000a0820` 等无符号 unique 槽（oracle 同槽有 pxVar17）→ link_symbols/高变量符号化域。
- ②in_RDX/in_RSI/in_RDI 未被 param 吸收（oracle param_1..3 吸收输入寄存器）→ FuncProto 参数恢复域（CALLSPEC/funcLinkInput 族已登记）。
- ③POSTFIX-RETIRE-0001 退役路线不变（本修复=层内误伤封堵，非层退役）。
- DP 停车链：numbering=0 前置**解除**（TODO row 619 已标解锁）；剩余前置 = GOLDEN-CONTRACT-PUSHABSORB-0001 root 裁决。

## 6. 机制 C 复核请求

本修复落 prettyprint GLUE 文本 pass——非机制 C 核心算法白名单模块，varmap 核心零改动故 C 通道 N/A；但 prettyprint 属 print 租约邻域（printres 车道在飞），**请 print 租约持有车道/独立 reviewer 复核两 hunk**：
- hunk1 = flush 旁路并联新判据（src/prettyprint.rs `has_symbol_driven_decls_walk_parens` + call site）；
- hunk2 = backfill declared 收集带括号分支。
证据：docs/api/prettyprint.md 2026-09-23 节 + commit ea71b739 ## Differential/## Verification 块 + /dev/shm/rugra-tests/sb-dupdecl/ 日志（baseline/variant/exp 对照全套）。

## 7. 证据文件（/dev/shm/rugra-tests/sb-dupdecl/，重启即丢）

httpd_base.log（2137/0/16 复现）/ httpd_varR.log+httpd_R_rel.log（2104/0/0）/ httpd_varP.log（flush 中立→9）/ httpd_varQ.log（backfill 中立→0，定因实验）/ httpd_varA…（隔离变体）/ curl_base.log+curl_varR.log+curl_R_rel.log（逐字节同）/ prettyprint.{base,exp1,variantA,variantP,variantQ,variantR}.rs（全变体源）/ commit_msg.txt。
