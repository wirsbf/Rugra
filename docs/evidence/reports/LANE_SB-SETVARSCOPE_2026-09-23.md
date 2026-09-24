# Lane sb-setvarscope 终报 — FUNCDATA-SETVARNODE-SCOPELOCAL-0001(DN 移交③)

- worktree: /dev/shm/rugra-worktrees/setvarscope, branch wt/setvarscope
- commit: **6007e957**(parent f8525d21 = master), hooks 全绿
  (gate health/docs sync/annotations/refs/机制 A 4/4)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- 写域: src/funcdata.rs + docs/api/funcdata.md + TODO_BOARD 行(varmap 域零改动)

## 符号尾三分支语义(一句话)

`setVarnodeProperties` 的唯一 `localmap->queryProperties` 中,
stackContainer(database.cc:1268)从查询 scope=ScopeLocal 本身起步:
**①ScopeLocal 符号命中**(findContainer,database.cc:952→entry getAllFlags
折叠)→**②in-scope discovery 停走**(database.cc:957-958→1271-1277
mapped|addrtied(+persist 仅全局)+property 折叠)→**③两者皆未命中才上溯
父/全局通道**(Rugra=Database 父通道,仅 RAM);命中任一本地分支即终结遍历,
父通道与名代理不再执行。

## 修复形态

`set_varnode_properties`(funcdata.rs:4978)在 RAM/父通道之前插入
`self.scope` 上的 `ScopeLocal::query_properties_ex`(varmap 既有接口零改动),
usepoint=`get_use_point` 有效地址(cc:31 形态,区别于 newVarnode 尾 INVALID
Address());entry 命中降级为 flags 折叠(DB-LOCALSCOPE-MAP-0001 分裂下与
`new_varnode_symbol_tail` 本腿同款处理)。

## 验收(诚实:恒等门实测证伪)

| 项 | branch | base(f8525d21 亲测) | 判定 |
|---|---|---|---|
| curl E2E | **2595/0/0** | 2563/0/0(skeleton +32) | defects/numbering 0;**非恒等**,Differential 逐处解释 |
| httpd E2E | **2337/0/0** | 2333/0/0(+4) | 同上 |
| next_url 投影 | MATCH | MATCH | 保持 |
| match_url 投影 | MATCH | MATCH | 保持 |
| parseconfig.constprop.0 投影 | MATCH(pin b2ace56a) | MATCH | 保持 |
| cargo test --lib funcdata(单线程) | 17 failed | 17 failed | 名单 diff 空 |
| 新单测 scope_local_leg | 3 分支全过 | — | PASS |

**证伪详情**:curl +32 = glob_word+6/glob_set+8/glob_range+5(调用实参
物化 `f(a+1,pos+1)`→`pos=pos+1; f(a+1,pos)` 两语句形)/main+7/myprogress+1/
getparameter+8(变量声明重排编号位移)/**file2string.part.0 −3 改善**(冗余
声明消除);httpd +4 = main+3/ap_fini_vhost_config+1(`uStack_40 =
uRam0000000000000028;` 类栈槽赋值)。机理:heritage(new_indirect_op/
placeInputs 系)与 condexe/coreaction 调用点的栈 varnode 取本地腿
mapped|addrtied 后,下游命名/物化面(varmap/printc/ruleaction 域)在 master
上暴露缺口——与 DN 停车分支 SB-F2STRING-ADDRTIED-PARAMRECOVERY-0001
(+1383)同族,量级 +32/+4。flag 语义本身与 oracle 逐字同
(database.cc:1271-1277)。

## 对 DN 链的解锁

DN 的 ruleaction 侧修复(4c53bfeb,RuleLoadVarnode→new_varnode_in_space)
与本修复落地后:set_varnode_properties 本体与 newVarnode 符号尾共享同一
ScopeLocal 腿语义,全部调用方(condexe/coreaction/heritage/funcdata 内部)
自动获得栈 addrtied 生产——DN 集成 4c53bfeb 时不再需要绕开本体;
下游收敛(+32/+4 噪音与 DN 的 +1383)同归 SETVARNODE-SCOPELOCAL-
CONSUMER-0001(新登记,域=varmap+printc+ruleaction,待派)。

## 已知限制(登记在案)

- entry 命中降级 flags 折叠(DB-LOCALSCOPE-MAP-0001 分裂,无活 SymbolEntry)。
- new_indirect_op newin 路径 usepoint=fd 入口−1 非 INVALID
  (FUNCDATA-INDIRECT-SYMBOLTAIL-0001 既有登记,语料内无可观察面)。
- 模块保持 L2,不宣称完成。

## 未决(移交 root)

1. commit 6007e957 待并入 master(root 串行集成;master 已进到 bf3f5064=
   2561/0/0,ED 的 −2 与本改动正交,合并后需重跑三门禁取合并态数字)。
2. SETVARNODE-SCOPELOCAL-CONSUMER-0001 派单(下游消费面收敛)。
3. /dev/shm/rugra-targets/{sb-setvarscope,svs-base} 留 root 清扫。
4. A/B 中断事故记录:首轮 base E2E 与重跑并发写同文件一度污染判据,
   已独占重跑定案(终值以本报告 sha256 为准:curl_branch
   749da309…/curl_base 0dc813ca…/httpd_branch 233cab7a…/httpd_base
   d2df9c35…)。
