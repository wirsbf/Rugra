# LANE REPORT — MYPROGRESS-OPPOOL2-CONSTSPLIT-0001 (wt/constsplit)

- worktree: /dev/shm/rugra-worktrees/constsplit, branch wt/constsplit
- base: master **faf0d593**(亲父,FC 车道 squash 集成)
- commit: **93107aff**(单 commit:ruleaction AddTreeState pRelType 机制 + docs/api + TODO 三行更新)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(锁树 ✓,annotation/refs hook ✓)
- 产物: /dev/shm/rugra-tests/sb-constsplit/(baseline/ after/ analysis/ + 双侧 drill);target: /dev/shm/rugra-targets/sb-constsplit/(留待复核/集成后清扫)

## ① constsplit 缺口一句话

myprogress ord150(与 parseconfig ord186 同族)的互补常量拆分 = RulePtrArith→`AddTreeState::calc_subtype` TYPE_SPACEBASE 臂 `hasMatchingSubType` 的 **extra**:oracle 对 `RSP(i)+(RCX+#-0x37)` 答 extra=1(PTRSUB `#-0x38`+INT_ADD `#0x238`),rugra 恒 extra=0——喂入端两缺口均在本 lane 写域外:**(a)** `TypeSpacebase.scope` 装的是 typefactory 建期全局 scope 克隆(typefactory.rs:1966-1973),从不查活跃 ScopeLocal,且 rugra 的 restructure 映射边界本身与 oracle 不同(ord150 时 `$$undef2[-0x138,-0x30)` 264B 合并数组 vs oracle outline[-0x138,-0x38) 256B+8B 边界;文本佐证 rugra `[264] aStack_138` vs oracle `outline[256]` 止于 -0x38);**(b)** Ghidra extra 的 TypePointerRel 路径(ctor ruleaction.cc:6032-6037 getAddressOffset 播种 nonmultsum)在 rugra 无喂入(实测 facing=plain `Pointer→Spacebase`,IS_PTRREL=false;typeop findResolve 为 identity 桩)。parseconfig ord186(FA2 switchnorm 计数修复后 155→186)为同族 Δ8(`#-0x4e8`+`#0x4e8` vs `#-0x4f0`+`#0x4f0`),同 -0x38/-0x30 边界差。

## ② 交付(ruleaction.rs,ruleaction.cc:5992-6336 逐行对照)

AddTreeState 补 `ct`/`p_rel` 字段 + pRelType 全机制:ctor 播种(6032-6037)/clear 重播种(5980-5983)/initAlternateForm 完整体(5999-6016)/spanAddTree 守卫(6236-6241,无符号 nonmultsum>=size)/calcSubtype STRUCT 臂 evaluateThruParent 检查(6314-6320)+尾部 ptrOff 移位(6332-6336);`ptr_rel_state` = IS_PTRREL+base.pointer_rel 的 isFormalPointerRel/getAddressOffset/getParent 所有权镜像。**当前管线无 rel facing → 全 dormant,行为零变化**(pRelType 路径状态 UNTESTED,喂入端补齐后转 MATCH 验证)。

后继登记(TODO_BOARD 三行):MYPROGRESS-OPPOOL2-CONSTSPLIT-0001 → ROOT-CAUSED;新增 `VARMAP-STACKBOUNDARY-0001`(P1,map 边界+活跃 scope 接线)与 `TYPEOP-PTRREL-FACING-0001`(P2,rel facing/findResolve;含 oracle extra=1 究竟走 map 边界还是 rel 播种的判别实验设计——两者代数同解,故本 lane 不武断)。两者落地后 ruleaction 侧再补 hasMatchingSubType arrayHint!=0 路径(nearestArrayedComponent*,type.cc:1669-1740/2971-3038)。

## ③ myprogress 新状态 + 三门禁(基线=亲父 faf0d593 亲测)

| 门禁 | 结果 | 基线 | 判定 |
|---|---|---|---|
| myprogress 投影 bisect | **ord150 不变**(同指纹 `c:237`/`c:dc9`;projection 字节级==改动前) | ord150 | △ 待 varmap/type 车道(根因域外) |
| parseconfig 投影 | **ord186 不变**(同指纹;注意:非 FC 报告的 ord155 switchnorm——FA2 车道已修,GETPARAM-SWITCHNORM-0001 行可关闭) | ord186 | △ 同族 |
| next_url 投影 | **MATCH** | MATCH | ✅ |
| match_url 投影 | **MATCH** | MATCH | ✅ |
| curl E2E 124 fn | **2377/0/0,输出字节级==基线** | 2377/0/0 | ✅ |
| httpd E2E 29 fn | **2238/0/0,输出字节级==基线** | 2238/0/0 | ✅ |
| gcc 审计 | 82 OK/25 FAIL==基线 | 82/25 | ✅ |
| ruleaction 单测 | 215/215 | — | ✅ |
| 全库 test --lib(单线程) | **失败集逐名==基线(18,FUNCDATA-TESTS-FLAKY-0001 既有集)**;并行跑 17↔20 波动=已知 flake,与改动无关 | 18 | ✅ |

## ④ 机制 C 复核请求(交付声明)

ruleaction.rs = 机制 B 白名单(主管线 Rule),单 agent 自检不可信,请求独立 Cross-Review(commit **93107aff**):
- 重点核对:①ctor rel 分支的 Ghidra 次序(baseType=parent 先于 size/isDegenerate 重导;multsum/nonmultsum 先零再播种);②span_add_tree 守卫的无符号比较(nonmultsum u64 vs size i64→u64)与放置点(两次 checkTerm 之后、合并判定之前);③calc_subtype STRUCT 臂 rel 检查在 extra 减法之后(6312-6321 次序)与 evaluateThruParent(0) 参数(ptrto/parent/wordsize/offset/ptrsize);④init_alternate_form 的 p_rel=None 先于 clear()(否则 clear 会重播种);⑤dormant 性断言(IS_PTRREL 当前管线不出现——可由四投影+E2E 字节级等价反证)。
- 复核期间只读;批准后由 reviewer 在集成提交加 `## Cross-Review: APPROVE`。

## ⑤ 判别实验存档(供 TYPEOP-PTRREL-FACING-0001 认领者)

oracle extra=1 的两条代数同解路径:(A) map 边界 fallback getSubType(-55) 命中 start=-56 容器(newoff=1);(B) rel 播种 nonmultsum=-1-55=-56 直出。判别:35c4:5ec(plain const -56,bnmc=0)双侧同答 -56——若 (B) 全局成立该 op 应答 -57,故 (B) 若真则仅 19e 的 facing 是 rel(per-op resolution),建议从 oracle golden 栈布局(`outline[256]` 边界 -0x38)+各 pass PTRSUB 常量序列切入。双侧 drill: sb-drill/curl.myprogress.oracle.drill(910 records, sha e26c9a32…)+ sb-constsplit/myprogress.rugra.drill。

## 回收

- LANE_REPORT 归档本文件;证据目录 /dev/shm/rugra-tests/sb-constsplit/(baseline/after 对拍+analysis+drill)与 sb-drill/curl.myprogress.oracle.drill **保留至复核与 root 集成**;
- /dev/shm/rugra-targets/sb-constsplit/ 留待 root merge 后按回收纪律清扫(复核若需改代码可复用增量缓存);
- oracle 环境 /tmp/rugra-ghidra-bfd-2.38 仍在(drill capture 已完成,后续判别实验可重建)。
