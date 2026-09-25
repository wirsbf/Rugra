# Lane DS 终报归档 — PARSECONFIG-CONDCONST-PHI-0001(Phase 2 第五函数)

- worktree: /dev/shm/rugra-worktrees/parseconfig, branch wt/parseconfig
- commit: **8eb8f976** (parent 94f3bf58 = master), tree clean
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- parseconfig.constprop.0 oracle projection: sha256 **b2ace56a…** (capture
  mode, 335 events / 335 snaps / 130099 ops,0 restarts;addr=0x3c80,BFD 符号
  `parseconfig.constprop.0`)

## 首分歧演进

| 状态 | 首分歧 | kind |
|---|---|---|
| master 94f3bf58 | ord 81 `mainloop:nodejoin` | V1_RESULT_COUNT_DIVERGENCE 1 vs 0 |
| +take_count_delta 适配器 | ord 83 `mainloop:condconst` | V1_RESULT_COUNT_DIVERGENCE 1 vs 0 |
| +condconst 两门移除+place_copy opInsert | ord 320 `universal:dominantcopy` | V1_OP_LINE_DIVERGENCE(0:903 vs 3e84:903) |
| +funcdata 一行(临时诊断,**已回退**) | **MATCH** | 335 stages / 130099 ops 全 identical |

## 根因(三层,双探针钉死)

1. **ord 81 = 纯记账缺口**:双侧 join 本体逐字节同执行(oracle probe 体与 pin
   b2ace56a 字节同;rugra probe 投影与无探针运行字节同)。apply#2 join
   3e78+3ce0(cb1=3e84:237/cb2=3d20:9b)、apply#5 join 3da8+3de1,两侧完全一致;
   ActionNodeJoin 缺 take_count_delta 适配器(15 个 leaf Action 已有同款),
   ActionState.count 恒 0。
2. **ord 83 = condconst phi 路径被两道 Rugra 专有门压制**:
   `use_multiequal=false` 硬覆盖 + `cond_const_done` 每函数一次门(在 apply#1
   ord 47 即置位,拦掉 apply#2 ord 83 的 firing)。oracle 在 ord 83 执行
   handlePhiNodes→placeCopy(`3ebd:8e9 COPY u:10000243=c:0`)+phi
   3ec0:46e slot 重写(coreaction.cc:4401-4426/4299-4337)。另 place_copy 原实现
   只 push alivelist 不挂块(oracle cc:4223 opInsert),新 COPY 无 parent(SNAP
   d=1)。use_multiequal 门同时改为忠实 per-space 语义
   (`fd.heritage.num_heritage_passes(fd.stack_space)>0`,cc:4522/
   heritage.cc:2779-2788,原裸 pass 忽略 Stack delay)。
3. **ord 320 = join 块地址区间未初始化(funcdata 域,占线未写)**:
   `node_join_create_block`(funcdata.rs:3268)跳过 oracle
   `setInitialRange(addr,addr)`(funcdata_block.cc:786,注释误判
   "informational only")→ join 块 stop=Address(0) →
   `Merge::buildDominantCopy` 读 `domBl->getStop()`(merge.cc:1168)把主拷贝
   建在 `0:903` 而非 `3e84:903`。**临时诊断一行补丁(set_initial_range,
   BlockBasic 已有 faithful 载体 block.rs:2347)实测投影 MATCH**;已按占线纪律
   回退,登记 `PARSECONFIG-JOINBLOCK-STOPADDR-0001`(TODO_BOARD,owner 待派)。

## 三门禁(基=亲父 94f3bf58 实测)

| 门禁 | 数字 | 基线 | 判定 |
|---|---|---|---|
| curl E2E compare | **2636**/0/0 | 2665/0/0 | PASS(−29:parseconfig 126→99、my_get_token 66→64,均向 golden 收敛;121 函数字节不变零回退) |
| httpd E2E compare | **2333**/0/0 | 2331/0/0 | PASS(+2=httpd main phi placeCopy 同族机制,0 缺陷 0 编号,## Differential 已说明) |
| next_url+match_url Phase 2 | 双 **MATCH** | 双 MATCH | PASS(保持) |
| parseconfig Phase 2 | 首分歧 81→**320** | 81 | PASS(后移;MATCH 证明=diag 投影) |
| gcc 语法审计 | 81 OK/26 FAIL | 81/26 | PASS(==基线) |
| cargo test --lib | funcdata:: 17 失败==master 逐字(单跑过) | 18±波动 | PASS(全量批跑 18↔20 为既有跨模块噪声,master 同在) |

golden 收敛证据:golden my_get_token 正含 `pcVar3 = (char *)0x0;` 零初始化
phi 模式;golden parseconfig 正含 `char *line; char *nextarg;` 声明(Rugra
master 侧是 pcVar4/pcVar5,修复后与 golden 同名)。

## 产物清单(本目录,重启即丢)

- curl.parseconfig.oracle.projection(pin b2ace56a)/ parseconfig_final·committed.projection
- first_bisect.txt / fix1·fix2·fix3·diag 投影与 stderr
- probe/build_probe.sh + nodejoin_probe_1204 + probe.stderr(oracle)/
  rugra_probe.stderr(rugra 侧,探针代码已从 src 移除)
- curl_master.c / curl_e2e.c / curl_committed.c(=gate run 字节同)/
  httpd_master.c / httpd_e2e.c
- master_tests.txt / fixed_tests.txt(批测对照)
- commitmsg.txt(含 ## Alignment Evidence 4/4 + ## Differential)

## 未决(移交 root)

1. `PARSECONFIG-JOINBLOCK-STOPADDR-0001`(P1,funcdata 域):一行
   set_initial_range,验收=parseconfig 投影 MATCH + 双语料零回退;
   sb-parseconfig lane 已留 MATCH 证明。
2. condconst propagate_constant MULTIEQUAL 臂 cc:4404 的
   `out.is_addr_tied()` 附加条件(Rugra 多加,oracle 仅
   varVn->isAddrTied()&&addr 相等)——本语料未触发(投影 MATCH 证明),
   属潜在偏离,建议并入下次 condconst/merge 域 touch 时修。
3. 历史收敛担忧复核:12/24 curl 超时的原始条件未在本 lane 复现(E2E 全绿);
   若后续 wave 在其它函数复现超时,按铁律 2 先读 condexe/deadcode 下游。
4. 机制 B2 正式 tests/oracle fixture 按 RAM 盘约定留 root 集成挑拣。
