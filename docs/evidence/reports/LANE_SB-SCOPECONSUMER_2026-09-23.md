# Lane sb-scopeconsumer 终报 — SETVARNODE-SCOPELOCAL-CONSUMER-0001（EE 落地后下游消费面回收）

- worktree: /dev/shm/rugra-worktrees/scopeconsumer, branch wt/scopeconsumer
- 基线: master effa7390（EE 并入后）;pre-EE 对照 = 958c94a0 独立 worktree
  /dev/shm/rugra-worktrees/scopeconsumer-base 亲测
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- 写域实际落点: src/coreaction.rs（ActionRestructureVarnode bootstrap——
  VARMAP-PARAMSTORAGE-BLOB-0001 同域先例,板上有登记的 param 条目修域）+
  docs/api/coreaction.md + docs/TODO_BOARD.md 两行;varmap.rs/printc.rs 零改动
  （读侧查询/同步链复核后确认已忠实,缺陷仅在 bootstrap 落位）

## 消费面缺口（一句话）

bootstrap 把所有 input-locked 参数符号按 `usepoint=None` 安装,addMap 的
empty-uselimit 分支给了**寄存器参数符号 addrtied+无限 uselimit**;oracle 的
ProtoStoreSymbol::setInput（fspec.cc:3153,3166-3169）对无 scope 认领的寄存器
存储回退 `restricted_usepoint`=fd−1（funcdata.cc:69）→非 addrtied+单点
uselimit——EE 并入 ScopeLocal 腿后,`set_varnode_properties` 开始对参数寄存器
槽上的后续 op 输出（调用实参算术 `pos+1`@rsi 等）折叠 entry flags
（mapped|addrtied）,下游 ActionMarkExplicit 强制 explicit
（coreaction.cc:3022-3048）+ ActionNameVars handleSymbolConflict 早臂挂名
（funcdata_varnode.cc:1000-1003）,暴露为 `pos = pos+1; f(a+1,pos)` 两语句形、
`_pos` mismatch 打印（printc.cc:2067-2083）与 getparameter `flag`(char*)
类型降级链。

## 修复形态

bootstrap ①先执行 `reset_local_window`（funcdata.cc:66-70 生命周期:窗口先于
localdb 符号安装）;②逐参 `scope.in_scope(space,offset,size)` 判定 usepoint——
窗口树内（MEMORY 类栈参数,localRange ∪ paramRange,varmap.cc:441-458）保留
None(INVALID)→addrtied;其余（寄存器参数）传 `Some(fd.baseaddr−1)`。经既有
add_symbol→add_map_entry_with_property 的 addMap 规则（database.cc:1149-1150）
自动落位:寄存器参数符号非 addrtied、uselimit={fd−1},`entry_in_use` 只在函数
入口点应答（=input varnode 自己的 usepoint,varnode.cc:696-703）。

## 验收（亲测,基=958c94a0 独立构建独立 E2E）

| 项 | branch(fix) | EE 后 master(effa7390) | pre-EE(958c94a0) | 判定 |
|---|---|---|---|---|
| curl E2E | **2516/0/0** | 2593/0/0 | 2561/0/0 | **超目标 ≤2561 达 45**;−77 |
| httpd E2E | **2335/0/0** | 2335/0/0 | 2333/0/0 | 残 +2=域外 FS-lift（见下） |
| next_url 投影 | MATCH | MATCH | MATCH | 保持（stage_bisect v1.2 identical,RUGRA_MIRROR=1） |
| match_url 投影 | MATCH | MATCH | MATCH | 保持 |
| parseconfig.constprop.0 投影 | MATCH | MATCH | MATCH | 保持（oracle pin 侧 /home/ls/Rugra/.fixture-staging/sb-parseconfig/） |
| gcc 审计 | curl 82OK/25FAIL;httpd 6OK/23FAIL | 同 | 同 | A/B 恒等 |
| cargo test --lib 单线程 | 18 failed（==基线逐字,fix 多 1 pass=EE 单测） | — | 18 failed | 名单 diff 空 |
| 新单测 | test_action_restructure_param_symbol_usepoint | — | — | PASS（regp/stkp 双分野三观察面） |

curl 逐函数（vs golden skeleton）:glob_word 27→**21**（==preEE,call 实参
`pos+1` 内联恢复）;glob_set 100→**80**（<preEE 92）;glob_range 85→**75**
（<80）;main 588→**575**（<581）;myprogress 76→**71**（<75）;
getparameter 751→**729**（<743,`Configurable*` 类型链恢复+`nextarg` 命名对齐
golden）;file2string 120→**119**（−4 改善,EE 的 −3 保持并扩大）。
`_pos`/`pattern_00` mismatch 族:preEE 17 处→fix 4 处（余 4=preEE 既有的
glob_range `pattern_00` 传播名,非 EE 族）。

## httpd 残差 +2 的定性（诚实记录）

main/ap_fini_vhost_config 各多 1 条 `uStack_40 = uRam0000000000000028;`
（`mov %fs:0x28,%rax; mov %rax,0x88(%rsp)` stack-protector canary 存）。
**golden 同位有该语句**:`local_40 = *(long *)(in_FS_OFFSET + 0x28);`——
即消费面修复后 Rugra 物化出了与 golden 同构的语句,残余纯表面形差:Rugra
lifter 把 `%fs:0x28` 提升为 RAM:0x28 persist 全局（golden 全语料 620 处
FS_OFFSET vs Rugra 0,preEE 已存在的横切缺口,非 EE 消费面回归）。已登记
`LIFT-FS-CANARY-FORM-0001`（P3,排队,x86_lift 域）。httpd ≤2333 的达标点在
该 lift 修复,不在消费面。

## 机制 C 复核请求

改动落点 = ActionRestructureVarnode 的 ScopeLocal bootstrap（varmap 核心算法
层的参数条目安装,VARMAP-PARAMSTORAGE-BLOB-0001 同域先例）。commit 含
## Alignment Evidence（fspec.cc:3147-3169 逐字签名+四类语义）与
## Differential 逐处解释。请求独立 cross-review:重点核对 ①usepoint 分支与
discoverScope 的等价性（register→fd−1/stack-in-window→INVALID）②
reset_local_window 前置后 markNotMapped 窄化生命周期不变 ③entry_in_use 单点
uselimit 只放行 fd−1 查询。

## 已知限制（登记在案）

- entry 命中降级 flags 折叠（DB-LOCALSCOPE-MAP-0001 分裂,EE 既有）。
- glob_range `pattern_00` 传播名（preEE 既有,makeRec/命名域）。
- FS 段 lift 形差（LIFT-FS-CANARY-FORM-0001,新登记）。

## 未决（移交 root）

1. commit 待并入 master（root 串行集成;合并后重跑三门禁取合并态数字）。
2. LIFT-FS-CANARY-FORM-0001 派单（httpd ≤2333 的达标点）。
3. /dev/shm/rugra-targets/{sb-scopeconsumer,sb-scopeconsumer-base} 与
   /dev/shm/rugra-worktrees/scopeconsumer-base 留 root 清扫;本 lane 产物
   /dev/shm/rugra-tests/sb-scopeconsumer/（A/B 输出+dump+投影+测试失败名单）。

## EK2 续跑复核（2026-09-23 14:4x,接手 session 独立重验）

前会话配额墙中断后由 EK2 接手;worktree 干净、a455c7c2 已提交、本报告与
TODO DONE 行齐备。以下数字全部由接手 session 在**不改动任何源码**的前提下
独立重跑复核（确定性检验,非转抄）:

- curl E2E: `compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c`
  → **skeleton 2516 / defects 0 / numbering 0**（124 函数）== 交付声明。
- httpd E2E: `compare_ghidra.py httpd_final.c tests/golden/ghidra_httpd_1204.c`
  → **skeleton 2335 / defects 0 / numbering 0**（29 函数）== 交付声明。
- 三投影 `stage_bisect.py --v1`（oracle 侧 sb-oracle/next_url、
  sb-oracle/curl.match_url、.fixture-staging/sb-parseconfig/curl.parseconfig）:
  三者均 **kind: MATCH,v1.2 stage and snapshot identical**（stages/ops 计数
  335/96457、340/80385、335/130099 双侧一致）。
- gcc 审计重跑: curl **82 OK/25 FAIL**、httpd **6 OK/23 FAIL** == A/B 恒等声明。
- 新单测 `test_action_restructure_param_symbol_usepoint` 单独重跑 **PASS**。
- canary 残差定性复核: golden `ghidra_httpd_1204.c` 同位确有
  `local_40 = *(long *)(in_FS_OFFSET + 0x28);`（行 3518/4225 等,语料共
  620 处 FS_OFFSET）;Rugra httpd_final 同位 2 条
  `uStack_40 = uRam0000000000000028;`——"golden 同构语句+表面形差"成立,
  归 LIFT-FS-CANARY-FORM-0001（域外）。
- 确定性: curl_fix1.c==curl_final.c、httpd_fix1.c==httpd_final.c 字节相同;
  result/curl_cur.c 已回流;oracle pin `ghidra/` HEAD=e40ed130… 复核通过。

**结论: a455c7c2 验证齐全,无需续修,交付 root 集成;机制 C cross-review
仍 PENDING（varmap 核心算法层白名单,集成前必须）。**
