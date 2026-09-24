# Lane GD/GD2 终报 — httpd L1 破零（HTTPD-CODEREF-SYMBOLIZE-0001）

- branch: `wt/l1zero`（基 b25bce7a）· commit **1cc776b1** · worktree /dev/shm/rugra-worktrees/l1zero
- 交付：httpd 真 L1 **破零达成并超额**（目标 ≥1 函数，实际门禁面 1 + 全量面 11）

## 破零函数清单（函数体逐字节 == canon golden 12.0.4）

| 面 | 函数 |
|---|---|
| 门禁面 29 fn | **ap_pregfree**（golden:5388，`apr_pool_cleanup_kill(param_1,param_2,FUN_0012dc80)` 全体逐字节同） |
| 全量面 473 fn | ap_pregfree, ap_close_piped_log, ap_create_request_config, ap_create_conn_config, ap_create_per_dir_config, ap_destroy_sub_req, ap_getword_conf_nc, ap_getword_white_nc, ap_add_input_filter, ap_add_output_filter, ap_register_input_filter |

byte-exact 真代码：门禁 0→1、全量 0→11（口径 = SCOREBOARD byte_exact_scan.py）。

## 根因（一句话）

canon golden 的 analyzeHeadless 前端对被分析代码以常量引用的代码地址建 Function
（如传给 apr_pool_cleanup_kill 的 0x12dc80 cleanup 回调）并以 FunctionSymbol 注册进
全局 scope → pushConstant TYPE_PTR→TYPE_CODE 臂（printc.cc:1786-1788）经
pushPtrCodeConstant（cc:1730 queryFunction）印 `FUN_0012dc80`；Rugra 裸驱动无该符号层，
印 `0x2dc80`（ap_pregfree 唯一 2 行残差）。

## 修复形态（driver 符号层三件套 + src 两点）

1. `examples/httpd_decompile.rs`：const 空间输入收割 + 入口三门验证（exec-range / 已知
   入口 / endbr64，门禁面 7 入口）→ FUN_ 命名通道扩展；打印期 per-function Architecture
   克隆挂只读符号 DB（action 侧查询通道保持 channel-absent = canon 基线管线语义不变；
   mirror 模式 dynsym-only 对齐 bare-BFD oracle）；golden emitter 双空行函数分隔。
2. `src/database.rs` add_function：buildType（database.cc:514-520 Code 类型 +
   namelock|typelock）+ addMap 折叠旗标（persist / addrtied；addrtied 为
   SymbolEntry::inUse cc:114-119 载荷）。
3. `src/printc.rs`：constant_leaf_text None/Unknown 臂 → code_entry_constant_text
   （cc:1730 解析链）；read-facing high 缺答回退 vn.v_type；opPtrsub spacebase 臂
   cc:1068-1069 TYPE_CODE → valueon（**PRINTC-SPACEBASE-TYPECODE-0001 解锁关闭**，
   ②PARTIALSYM 仍 OPEN）。

全部 Ghidra 引用行亲核（printc.cc:1055-1097/1722-1745/1780-1795、database.cc:505-525/
110-122/1125-1155、typeop.cc:700-712、coreaction.cc:5014-5040 逐字比对通过）。

## 三门禁（基线 = 亲父 b25bce7a，GD2 亲测 fast-release）

| 门禁 | 亲父 | 本交付 | 判定 |
|---|---|---|---|
| curl E2E | 1995/0/0 | **1995/0/0 字节恒等** | 过 |
| httpd 门禁面 | 2072/0/0 | **2070/0/0**（仅 ap_pregfree 2→0，31 fn 逐字不动） | 过 |
| httpd 全量 473 | 25997/0/0 | **25989/0/0**，逐函数零回退（3 改善：ap_pregfree 2→0 / ap_close_piped_log 2→0 / ap_open_piped_log_ex 30→26；31 非空白行差=0x→FUN_ 符号化，470 空白行=分隔布局） | 过 |

投影：next_url(335/96457) / match_url(340/80385) / parseconfig(335/130099)
**MATCH×3**；getparameter ord351 / myprogress ord399 / httpd main ord83 前沿零移动。
确定性：门禁面双跑 + 前代 FINAL2 三方字节恒等。单测 database 57/57、printc 12/12；
annotations --all + refs --strict 过。

## 残差如实登记

- gcc 审计 8OK→7OK：ap_pregfree 孤立块引用 `FUN_0012dc80` 无前向声明 —— canon
  golden 孤立块同形（定义块在 golden:5034，不在 Rugra 29/473 函数选择面内）；
  FUN_ 定义块本体未入反编译面（golden 2010 vs 473 选择差）= 后续扩展面。
- ap_pregcomp 的 `PTR_apr_pool_cleanup_null_0019cfe0` vs `*(undefined8 *)(in_RIP+0x9cfe0)`
  = 既有 in_RIP 族，不动。
- 注意（root）：master b5b949dd 的 GH 核心类型修正（lVar/sVar 前缀）不在本 lane 基线内；
  集成时若前缀变体影响其他函数，以 master 重跑门禁为准（本 lane 语义面不受影响：
  符号化层与类型前缀正交）。

## 证据

/dev/shm/rugra-tests/l1zero/（gates/=GD 前代产物：BASE/FINAL2/curl_BASE/curl_MINE/
httpd_full_{BASE,MINE}；gd2/=GD2 复验：httpd_gate.c{,_run2} + curl.c + 六投影）。
回收：待 root 集成后清 /dev/shm/rugra-targets/sb-l1zero 与 rugra-tests/l1zero。
