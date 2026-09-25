# Lane GJ 终报 — GD2 方法镜像到 curl 驱动（CURL-CODEREF-SYMBOLIZE-0001）

- branch: `wt/coderefsym`（基 c4173c54 = GD merge 态）· commit **1681ea84** · worktree /dev/shm/rugra-worktrees/coderefsym
- 交付：curl 驱动代码引用函数符号层（打印期 FunctionSymbol DB），驱动层零 src 改动

## 形态确认（工单②抽样结论）

curl 语料确有该形态，共 **2 个函数、5 处常量**：

| 函数 | Rugra 前（裸地址） | Rugra 后 = golden |
|---|---|---|
| main | `curl_easy_setopt(lVar10,0x4e2b,0x3460)` | `curl_easy_setopt(lVar10,0x4e2b,my_fwrite)`（golden:932） |
| main | `curl_easy_setopt(lVar10,0x4e58,0x34d0)` | `curl_easy_setopt(lVar10,0x4e58,myprogress)`（golden:990） |
| _start | `(0x25a0,…,0x5400,0x5470,…)` | `(main,…,__libc_csu_init,__libc_csu_fini,…)`（golden:1046，顺带符号化） |

golden 全量仅 `FUN_00102020`（PLT0，已在 ledger）一处分析器发现函数——curl 缺的是 **DB 函数层**（ELF 名已在 symbol_table），不需要 httpd 侧的 const 收割+三门验证+FUN_ 命名通道（语料闭合于 124-function ledger）。

## 修复形态（GD2 镜像 + curl 两点适配）

1. `DecompileRequest` 新增 `fn_symbol_entries`（worker 协议 v3）：控制器 canon 模式=exec-range ledger 函数集（124−48 EXTERNAL=**76**）；bare-load mirror=readLoaderSymbols 全 loader 符号（architecture.cc:346-359，无类型区分）；地址排序去重。
2. worker `decompile_request`：**action done 后**安装打印期符号 DB = program_db 内容克隆（保数据符号+readonly range，字符串渲染通道不回退）+ 76 个 `add_function(addr,name,1)`（consume_size=1=min_funcsymbol_size 默认），挂 per-function Architecture 克隆 symboltab（httpd 同款安装契约；action 阶段查询通道零变化）。
3. 消费链已在 master（GD2 交付）：constant_leaf_text None/Unknown 臂 → code_entry_constant_text → query_function_addr（printc.cc:1730/1736 通道）。

## 门禁（基线=亲父 c4173c54 亲测，fast…release）

| 门禁 | 亲父（亲测） | 本交付 | 判定 |
|---|---|---|---|
| curl E2E | 1822/0/0 | **1818/0/0**（只降） | 过 |
| httpd 门禁面 | —（同源码同构建） | 1754/0/0（32 fn） | 过（=c4173c54 现值） |
| httpd 全量 473 | —（同上） | 24537/0/0 | 过（=c4173c54 现值） |

- GD2 时代 httpd 2070/25989 与现值之差全部来自已入 master 的 GH 融合（b5b949dd coretype）；本 diff 仅 examples/curl_decompile.rs，httpd 二进制非干扰。
- 逐函数差分（fresh BASE vs MINE）：仅 main+_start 变化，5 行全部 golden 方向，122 函数字节恒等 = 零回退。
- **五投影 MATCH×5**：next_url(335/96457) / match_url(340/80385) / parseconfig(335/130099) / getparameter(371/913373) / myprogress(402/84249)。旧 ord351/ord399 前沿已随 master GH 融合闭合，本车道零移动实证。
- 双跑字节恒等；gcc 审计 fail 集逐名恒等（102OK/22FAIL）。
- cargo test --lib：跳过（零 src 改动，example-only diff 无单测面）。

## 残差如实登记

- main/_start 孤立块 undeclared 计数 +16：canon golden 孤立块同形（golden main 块同样裸引 `my_fwrite` 无前向声明）——与 GD2 httpd 残差同性质。
- bare-load mirror 模式的 readLoaderSymbols 全符号集为通道实现（RUGRA_MIRROR 投影路径不经打印 DB，验证面=canon 门禁）。

## 证据与回收

- 证据=/dev/shm/rugra-tests/coderefsym/（curl_BASE/curl_MINE(+run2)/httpd_gate/httpd_full/五投影/audit/commit_msg/patch；投影大文件已清，compare 结论在报告内）。
- /dev/shm/rugra-targets/sb-coderefsym 留待 root 集成后清（构建缓存）。
- worktree result/curl_cur.c 已回流（gitignored）。
