# Lane EI2 终报 — RANGEUTIL-VSEMPTY-0001 (wt/vsempty, 续跑 EI + CR8 返工)

- worktree: /dev/shm/rugra-worktrees/vsempty, branch wt/vsempty
- commits: **dbd5d89b** (fix) + 042eb9cb (hash fill) + **99f023f4** (CR8 返工); base = 5ff281e0
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
  (投影 pin: sb-oracle/curl.getparameter.constprop.0 / next_url / match_url,
  sb-parseconfig/curl.parseconfig)
- 日期: 2026-09-23; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-vsempty

## CR8 返工 (commit 99f023f4, 2026-09-23)

CR8 对 dbd5d89b 裁定 REJECT（两 MISMATCH,潜伏语义雷类,当前语料不可见）→ 已修:

- **M-A** RuleRangeMeld OR 臂: legacy `union`(wrapping 一律两片)→ 忠实版
  `circle_union`(cc:360-444),映射 {0→0,非零→2};"full→1" 特判删除,满覆盖经
  translate_to_op→Err(1)→COPY(1)=cc:1412-1430 原路径;legacy union 加禁用隔离注记。
- **M-B** CircleRange 相等: derive(PartialEq)→手写镜像 hh:331-336
  (isempty 不等→false;双空→true 不比残留 mask/step;left/right/mask/step 四字段)。
- **obs①** 成员版 new_stride/new_domain 死代码删除(tombstone 注记)。
- **obs②** set_stride 逐字重写 cc:707-722(early-return/旧步长快照/iseverything 塌缩)。
- **obs③** 三条 r1 遗留登记 `RULEMELD-FIDELITY-RESIDUE-0001`(copySymbolIfValid/
  isHeritageKnown 代理/SUBPIECE nzmask)。
- 单测 +3: eq 双空残留语义 / circle 级 wrapping 合并 / 规则级
  (200<sV)||(250<sV)→INT_SLESS(200,V) 单区间重写。rangeutil 51/51。
- 验证(返工态全恒等 dbd5d89b 态,符合"语料不可见"预判): curl 2563/0/0 与
  httpd 2333/0/0 字节恒等;gp ord65 738 不变;三投影 MATCH;gp 投影新旧
  stage-bisect MATCH(仅 META tree hash 行异)。
- **CR9 复审请求**: 99f023f4 取代 dbd5d89b 的被 REJECT 项。
- **ET 车道注意**: ET(constgen)基于 042eb9cb 并行,本返工落在 wt/vsempty
  的 042eb9cb 之上(99f023f4),ET 集成时需 rebase。

## 根因(一句话)

`ValueSetSolver::establish_value_sets` 的 worklist 扩展与 `ValueSet::iterate`
的输入链都是 TODO 壳——sink 的 defining-op 输入从不进系统、迭代无输入可推,
求解器对全部 guard sink 恒 empty range(LoadGuard 退化为全窗)。

## 修复(commit dbd5d89b, 全部对照 12.0.4 逐行核对)

1. `set_varnode` written 分支经 `get_def()` 初始化 opCode/numParams
   (cc:1516-1527, INDIRECT→COPY);删除 `set_defining_op` 注入胶水。
2. `establish_value_sets` 全量 worklist 扩展(cc:2450-2498)+
   `input_ids/input_sizes/out_size` arena 活读暂存(id 稳定 ≡ C++ 活链)。
3. `iterate_node/iterate_body`(cc:1611-1737)全量;`solve` 两调用点改接。
4. push_forward_unary/binary(cc:1093-1367)、pull_back
   ZEXT/SEXT/SLESS/SLESSEQUAL/CARRY/SRIGHT(cc:754-998)、
   intersect/invert/contains_range/translate2Op(cc:549/533/301/1424)忠实化
   + 移位 UB wrapping 防护。
5. ruleaction RuleRangeMeld restype 码流对齐 cc:1403-1437
   (translate_to_op→Result,Err 码落 COPY(1)/COPY(0)/cannot 臂,
   补 EQUAL/NOTEQUAL/SLESS 翻译臂)。
6. heritage.rs 的 [DBG VSProbe] 探针已删(净零,与亲父逐字节同)。
7. 文档: rangeutil.md/ruleaction.md 同步;roadmap rangeutil L3→L2 降级更正
   (旧 L3 声称失实——约束生成族仍为结构壳)。

## 门禁数字(全部亲跑,产物在本目录)

| 门禁 | 数字 | 基线(亲父 5ff281e0) | 判定 |
|---|---|---|---|
| getparameter ord65 | 738 vs oracle 740(**不变**;投影 vs 亲父 stage/snapshot identical) | 738 | 残差 -2 保持 |
| curl E2E | **2563/0/0** | 2561/0/0 | PASS(硬门 0/0;+2 见下) |
| httpd E2E | **2333/0/0** | 2333/0/0 | PASS 字节恒等 |
| next_url 投影 | **MATCH** | MATCH | PASS 保持 |
| match_url 投影 | **MATCH** | MATCH | PASS 保持 |
| parseconfig 投影 | **MATCH** | MATCH | PASS 保持 |
| rangeutil tests | 49/49 | — | PASS |
| heritage tests | 15/16 | 15/16(test_heritage_creation) | 预存,无关 |

curl +2 归因(逐函数 A/B,基线亲跑 curl_base.log):
- file2string.part.0 −2: uStack_148/uStack_144/cVar18 标量并成 `uint[66]
  auStack_148`,向 golden 数组形态收敛(LoadGuard 真窗口驱动 varmap)。
- match_url +4: 四条栈声明浮现(aiStackY_1040 等),同为 varmap 形态变化,
  零表达式级变化(非 RuleRangeMeld)。defects=0/numbering=0。

## 未决(移交 root)

1. **RANGEUTIL-CONSTGEN-0001**(新排队): finalize WidenerFull 对 load 守卫
   爆窗(size≈0x2fffffb70 vs oracle [fb08..ffa7] state=2)——landmark/equation
   只能来自约束生成族(apply_constraints cc:2105 / constraints_from_path
   cc:2185 / constraints_from_cbranch cc:2210 / generate_constraints cc:2248 /
   generate_relative_constraint cc:2351 全为结构壳)。前置=FlowBlock 支配查询
   +CircleRange::pullBack(PcodeOp*)。修后 ord65 预期 738→740。
2. 机制 C Cross-Review: PENDING(rangeutil/ruleaction 域;commit 带
   ## Alignment Evidence 4/4 + ## Differential)。
3. B2 正式 fixture 按 RAM 盘约定留 root 集成挑拣。
4. 根因链上一环的 oracle 側证据: gp.oracle.hnlc.stderr(HNLC-DBG)与
   gp.rugra.vsprobe 行(修复前)/gp.rugra.final2.stderr(修复后)。

## 回收说明

- 本目录保留全部证据投影/日志直至 root 集成后清扫;tmp/ backup/ 已删。
- /dev/shm/rugra-targets/sb-vsempty(~构建缓存)留给 root merge 后统一回收。
