# LANE REPORT — MYPROGRESS-SETCASTS-ORD399-0001 (wt/setcasts399, Lane FV2 续跑)

- worktree: /dev/shm/rugra-worktrees/setcasts399, branch wt/setcasts399
- base: master **9458a61b**(FO lane 尾;前代 FV 会话连接中断,**零 src 遗产**——本 lane 从复现起步)
- commit: **81cdfa2b**(core: setcasts SUBPIECE/PIECE output token overrides reach oracle parity;含 ## Alignment Evidence 4/4 + ## Differential + Cross-Review REQUESTED;hooks 全绿:gate health/annotations/refs/机制 A)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(锁树 ✓)
- 产物: /dev/shm/rugra-tests/sb-setcasts399/(bisect_baseline_ord399.txt、bisect_fix_MATCH.txt、probe1-3 探针、fix1.rugra.projection、curl/httpd A/B 对照、base/fix_failures.txt、commitmsg.txt);target: /dev/shm/rugra-targets/sb-setcasts399/(留 root merge 后清扫)
- 写域遵守: src/coreaction.rs 仅 ActionSetCasts(cast_output token 分发+subpiece_output_token 新函数)——与 FW2(InferTypes,同文件区间分治)零重叠;+docs/api/coreaction.md+TODO_BOARD 本行

## ① 基线复现(任务前置判定)

9458a61b 干净树亲测:myprogress 投影 bisect 首分歧=**ord399 `universal:setcasts` result/count 5 vs 6**(V1_RESULT_COUNT_DIVERGENCE),与 sb-stackbound 登记**逐字复现**(bisect_baseline_ord399.txt)——任务为活缺口,非纯归因。注意:**FM 并集在 FW2 验证中(781046c2),本修复在 9458a61b 基线独立成立**;FW2 并集 rebase 时 setcasts 臂不与其 InferTypes 区间冲突,若并集后 5vs6 形态变化需重跑本验收。

## ② 根因(三层探针钉死,探针已全部移除)

ord399 SNAP diff:rugra 多一枚 `3519:5fe CAST u:100001e1:4 ← n:register:0:4` 使 `3519:99 INT_SLESSEQUAL` in1 变 CAST 输出(oracle 直读),下游 3549:c1/3549:5fe unique 顺移。

1. **probe1**(SLESS 族 cast 决策):3519 slot1 的 curtype=**undefined4(Unknown meta)**→castStandard(int4,unknown4,care=true)=cast;oracle 侧要无 cast 必须 curtype∈{int4,bool4}。
2. **probe2**(setcasts 入口全 op 高类型 dump):`SUBPIECE@3515:336` 的输出 EAX4 在 setcasts **开始时 high=int4**(与 oracle 一致!)——int4 是 oracle 无 cast 的充要条件,降级发生在本 Action **执行中途**。
3. **probe3**(逐 op 跟踪):降级精确发生在处理 `op=3515 SUBPIECE`(EAX4 自己的 writer)那一趟——`after op=3512:SUBPIECE eax4_high=int` → `after op=3515:SUBPIECE eax4_high=undefined4`。

**根因链**:cast_output 对 SUBPIECE 的 token 计算落入 output_metatype 泛化臂(=TypeOpFunc 构造器输出基 typeop.cc:2117 TYPE_UNKNOWN)得 token=undefined4≠outHighType(int4);走进 cc:2569-2571 implied 非指针臂 `outvn->updateType(undefined4)`(varnode.cc:456 实例类型直写+high typeDirty)降级 EAX4;3519:99 后续读 facing=undefined4 → 多余 CAST。**oracle 的 TypeOpSubpiece::getOutputToken(typeop.cc:2142-2159)是覆写**:①findTruncation 字段臂 ②输出 DEF-facing 非 TYPE_UNKNOWN ③factory INT 基兜底——永不为 undefined,token==int4 在 cc:2544 短路,零副作用。

## ③ 交付(镜像两个覆写)

- `subpiece_output_token`(`// Ghidra: typeop.cc:2142`):三段逐字镜像;find_truncation 经 `fd.union_map` 只读消费(=TypeUnion::findTruncation type.cc:2185);复合偏移=小端 lsb/大端 inSize-outSize-lsb(typeop.cc:2195-2207);非尺寸匹配字段穿透。
- cast_output token 分发补 CPUI_PIECE 臂(typeop.cc:2063-2072):DEF-facing INT/UINT 即 token,else factory UINT 基。
- output_metatype 表零改动(INSERT 仍 Unknown=无覆写);**全部探针([DBG]/[DBG-TRACE])已移除**,diff 纯 122 行净增。

## ④ 验收(基线=9458a61b 本 worktree 亲测 A/B)

| 门禁 | 结果 | 基线 | 判定 |
|---|---|---|---|
| **myprogress 投影** | **MATCH**(402 stages/84249 ops,首分歧 399 **清零非后移**)=**第四全量 MATCH 函数** | ord399 5vs6 | ✅ |
| next_url 投影 | MATCH 保持 | MATCH | ✅ |
| match_url 投影 | MATCH 保持 | MATCH | ✅ |
| parseconfig 投影 | MATCH 保持(335/130099) | MATCH | ✅ |
| curl E2E 124 fn | 3994/**0/0**;delta=6 函数 42 行**全部 undefined→具体类型 golden-closer 行内拼写升级**(myprogress `(int)SUB84`→`SUB84`+`(undefined1)`→`(char)`;match_url/helpf/file2string/my_get_line `(undefined8 *)`→`(uint8 *)`;main 11×`(undefined4)`→`(uint)`),skeleton 总数不变 | 3994/0/0 | ✅ |
| httpd E2E 29 fn | 2767/**0/0**,**与基线逐字节恒等** | 同 | ✅ |
| gcc 审计 | curl 101OK/21FAIL+httpd 6OK/23FAIL==基线 | 同 | ✅ |
| test --lib(串行) | 18 failed 失败集与基线**逐名相同**(diff 空;1682 passed) | 18 | ✅ |
| 双跑确定性 | curl/httpd 字节恒等 ×2 | — | ✅ |

注:curl 3994 与历史 lane 报告的 2152 差异=FO 两 commit(bc22461d→9458a61b)自身演化,本 lane 亲测基线同刻度 A/B,非本修复效应。

## ⑤ 机制 C 复核请求(coreaction 主管线 Action)

commit **81cdfa2b** 请求独立 cross-review,复核者**自读**(勿采信本报告):
1. typeop.cc:2142-2159(TypeOpSubpiece::getOutputToken)vs src/coreaction.rs:5996 subpiece_output_token——三段短路序/尺寸门/复合偏移小端大端/union 臂只读语义(fd.union_map ≡ TypeUnion::findTruncation 的 getUnionField 只读查询);
2. typeop.cc:2063-2072(TypeOpPiece)vs cast_output CPUI_PIECE 臂——metatype∈{INT,UINT} 判定与 UINT 兜底;
3. 拦截位:两臂在泛化 metatype 臂之前,INSERT 仍走 Unknown(Ghidra TypeOpInsert 无覆写)是否属实;
4. base_type_for detached-fixture 兜底与既有 lane 约定(2026-09-23 MATCHURL-SETCASTS-337 token 工厂化)一致性。

## ⑥ 跨车道协同

- **FW2(FM 并集 781046c2)**:本修复独立于并集;并集 rebase 后请重跑 myprogress 投影验收(预期 MATCH 保持,若 InferTypes 改变 EAX4 上游类型状态,setcasts 臂的判定自动跟随 oracle——token 计算是纯查询)。
- 旧 `PIPE-ACTION-COUNT-0001C` 残差登记(castOutput union needsResolution 臂)不受本修复影响。
