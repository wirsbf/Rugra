# LANE REPORT — MYPROGRESS 双根因修复 (wt/andcommute)

- worktree: /dev/shm/rugra-worktrees/andcommute, branch wt/andcommute
- base: master **dc62a4bf** (亲父,tree clean)
- commits: **99886d14**(RuleAndCommute 收益门) → **21426fb2**(find_condition 步进) → **c5a20182**(docs 收尾)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(锁树校验 ✓,hook 健康 ✓)
- 产物: /dev/shm/rugra-tests/sb-andcommute/;target: /dev/shm/rugra-targets/sb-andcommute/

## ① 两修复确认

### D1 — MYPROGRESS-ANDCOMMUTE-GATE-0001(commit 99886d14)
RuleAndCommute::apply_op 按 ruleaction.cc:1532-1626 全结构重写:
- 唯一无条件短路 = LEFT + othervn 常量 + `shiftvn->loneDescend()==op`(cc:1573-1580);
- 其余情形**强制** cc:1582-1603 收益门:orvn `is_written` 且 def∈{INT_OR,PIECE}(INT_OR 四道掩码门/PIECE 低半=in(1)·高半=in(0)<<in(1).size*8),否则 `continue` → LOAD 输出不再被非法 commute;
- 补 cc:1556 `isHeritageKnown`;`othermask==0/fullmask` 移到调整后(cc:1569-1570);
- **cc:1566 `(fullmask<<sa)&&fullmask` 按字面移植**(逻辑 && → 0/1 门,仅 othermask==1 拒)——Ghidra 源码怪癖保留,决策记录于代码注释与 commit message;
- 全部移位 `wrapping_*`(uintb 环绕)。
- 单测:旧 `test_and_commute_right_shift` 断言的是缺陷行为,已替换为 3 个 oracle 语义用例(LOAD 拒 NO_CHANGE / LEFT 快路 CHANGE / INT_OR disjoint 臂 CHANGE)。

### D2 — MYPROGRESS-INT2FLOATCOLLAPSE-0001(commit 21426fb2)
**关键发现**:RuleInt2FloatCollapse 本体已在 base 由 EZ 车道落地(ruleaction.rs:14817,逐行核对 cc:9845-9895 无需改动)+ oppool1 注册(action.rs:1739 // 5637)。**真缺口 = FlowBlock::findCondition**(block.cc:839-858):
- Ghidra 第一循环每跳 `bl1=cond; edge1=0` 步进,最终 `slot1 = bl1->getInRevIndex(edge1)` 取 **cond 正下方块**对 cond 的出边槽位(= dir2unsigned 判向);
- Rugra 误用调用方原始 bl1/edge1 → 菱形 CFG(walk≥1 hop)恒返臂块唯一出边槽 **0** → Int2FloatCollapse 判向测试((basevn<0) 需 dir2unsigned==1 / (-1<basevn) 需 !=1)永不满足 → **规则在 walked CFG 上永不 fire**;
- 修复 = `cur_bl1/cur_edge1` 随 walk 步进(src/block.rs:1870)。
- 效果:3594:501 MULTIEQUAL 折叠为 `INT2FLOAT(ZEXT(RSI)→reg:1200:4)` + 9 字节 zext(preferredZextSize(8));358f:177 / 36a0:224+526 悉数死灭,与 oracle 快照一致。

## ② myprogress 投影新状态

- 双投影 bisect(oracle capture sha 96522748…,RUGRA_MIRROR=1 全家 env):
  - 首分歧 **ord 28 → ord 150**;rugra stage 数 **299 → 402/402** 追平 oracle;ops 68011 → 84020(oracle 84249);
  - **ords 1-149 stage+snapshot identical**(含全部 oppool1 窗口);
  - 新首分歧 ord 150 `universal:fullloop:mainloop:oppool2` op-idx 86:`35cf:5ee INT_ADD c:238↔c:237` + `35cf:5ef CROSSBUILD c:dc8↔c:dc9`(互补 ±1 拆分,终值相同)——输入 IR 相同下的池内 Rule 行为差,**新登记 MYPROGRESS-OPPOOL2-CONSTSPLIT-0001**(P1 OPEN);
  - DT 未决问题 2 解答:XMM1 族(367e R8)修复后双侧一致(pass1 内均未折叠,无 pass2 分歧)。
- `--func myprogress` 文本:**67 行**(基线 71/75 量级,只降不升 ✓),defects=0/numbering=0;残差=varmap/typeprop 层(register0x1200 打印、aStack 命名、typeprop 不收敛告警),系 +2 unique/+3 ops 消除后的重排,形态变化属预期。

## ③ 三门禁 + 投影

| 门禁 | 结果 | 基线(亲父 dc62a4bf 口径) | 判定 |
|---|---|---|---|
| curl E2E 124 fn | skeleton **2507**/defects **0**/numbering **0** | ≈2511/0/0 | ✅(-4) |
| httpd E2E 29 fn | **2282**/0/0 | ≈2282/0/0 | ✅(==) |
| gcc 审计 | 82 OK/25 FAIL | 82/25 | ✅(==) |
| next_url 投影 | **MATCH**(335/96457) | MATCH | ✅ |
| match_url 投影 | **MATCH**(340/80385) | MATCH | ✅ |
| parseconfig 投影 | ord155 switchnorm 2v0 | constgen 车道登记残差(同指纹) | ✅ 零影响(ords 1-154 identical) |
| ruleaction 单测 | 215/215 | — | ✅ |
| 全库 test --lib | 1677 pass/18 fail | 18 预存集(funcdata 族+heritage_creation) | ✅(零新增) |

## ④ 机制 C 复核请求(交付声明)

本车道两处代码提交均属主管线 Rule / 核心图查询(**ruleaction.rs=机制 B 白名单;find_condition 为 block 核心查询,消费方=Int2FloatCollapse/IgnoreNan**),单 agent 自检不可信,请求独立 Cross-Review:
- **99886d14**:重点核对 break/continue 控制流映射、cc:1566 逻辑&&字面形态、PIECE 高半移位量、LEFT 快路先于 is_written 的顺序;
- **21426fb2**:重点核对 bl1/edge1 步进时机(先记 `cur_bl1=cond` 再推进 cond)、bl2 链语义、返回槽位语义;
- 复核期间只读;批准后由 reviewer 在集成提交加 `## Cross-Review: APPROVE`。

## 回收

- LANE_REPORT 归档 /dev/shm/rugra-reports/;证据目录 /dev/shm/rugra-tests/sb-andcommute/(投影×4+bisect×4+E2E 双语料+commit msgs)**保留至复核与 root 集成**(机制 B2 fixture 挑拣入库);
- /dev/shm/rugra-targets/sb-andcommute/ 留待 root merge 后按回收纪律清扫(复核若需改代码可复用增量缓存)。
