# LANE REPORT — DT 第六函数归因 myprogress (wt/myprogress)

- worktree: /dev/shm/rugra-worktrees/myprogress, branch wt/myprogress
- base: master **94f3bf58** (tree clean, docs-only 登记 commit 见下)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b (锁树校验 ✓)
- target: curl `myprogress` @ **0x34d0** (nm: `00000000000034d0 T myprogress`,477 字节)
- 产物: /dev/shm/rugra-tests/sb-myprogress/;target: /dev/shm/rugra-targets/sb-myprogress/

## ① 双侧投影 + bisect 首分歧

- oracle 投影 (capture 模式,未入 metadata pin):
  `bash tools/run_stage_projection_oracle.sh curl 0x34d0 myprogress`
  → events=402 snaps=402 ops=84249 restarts=0 bytes=5687045
  sha256=965227487df3c2b91ca680c7bbc070545bbecc6e0459c5e77828389d9e149c11
  安装于 /dev/shm/rugra-tests/sb-oracle/curl.myprogress.oracle.projection
- rugra 投影 (RUGRA_MIRROR=1, release @ 94f3bf58): stages=299 ops=68011
- `tools/run_stage_bisect.sh` → **kind=V1_OP_LINE_DIVERGENCE, ord 28
  `universal:fullloop:mainloop:stackstall:oppool1` (首轮) op-idx 24**:
  - oracle `3515:39e INT_AND out=n:register:18:8 in=n:register:0:8,c:ffffffff:8`
  - rugra  `3515:39e INT_RIGHT out=n:register:18:8 in=u:1000010c:8,c:a:4`
           `3515:524 INT_AND out=u:1000010c:8 in=u:23e00:8,c:3fffffffc00:8`
- ordinals 1-27(含 heritage/infertypes 首轮)全 stage/snapshot identical;
  @END 28 计数双侧同为 result=729 count=729 tests=0 apply=8(纯 SNAP 内容分歧)。

## ② 根因(一句话)

**RuleAndCommute 移植缺陷(ruleaction.rs:4679)**:Ghidra 对非
(LEFT+const+loneDescend) 情形强制 orvn.def∈{INT_OR,PIECE} 收益门
(ruleaction.cc:1582-1603),orvn=LOAD 输出时不得 commute;Rugra 把该门
误删,对 INT_RIGHT 无条件 commute `AND(RIGHT(load,10),0xffffffff)` →
`RIGHT(AND(load,0x3fffffffc00),10)`。

### SNAP28 全量 diff 六块逐块归因(oracle 198 ops vs rugra 201)

| hunk | 现象 | 归因 |
|---|---|---|
| L25-26 | 上述 3515:39e 双 op 反型 | **D1 AndCommute 门缺失** |
| L76a78 | rugra 多 `358f:177 INT2FLOAT(RSI)` 存活 | **D2 RuleInt2FloatCollapse 未移植**(signed 路未死) |
| L81-83 | oracle `3594:501 INT2FLOAT(ZEXT(RSI):9)`+zext@:525 vs rugra `3594:501 MULTIEQUAL(BUILD)` | D2(MULTIEQUAL 未折叠;双侧同 seqnum 证 PullsubMulti 同建,oracle 原地重定义) |
| L147 | 367e zext `u:10000104:9` vs `u:10000114:9`(+0x10) | D1 残差:D1 多分配 2×8B unique,VarnodeBank::createUnique 全局 bump(varnode.cc:1265-1269) |
| L149 | 367e zext 时间 523 vs 525 | D1 残差(全局 op 计数 +2) |
| L152+ | rugra 多 `36a0:224 INT2FLOAT`+`36a0:526 ZEXT(RSI)` | D2(36a0 Unsigned2Float 结果未被折叠消费) |

- D2 机制:cvtsi2ss r64 负数双路径(js→(X>>1)|(X&1)+T+T / jns→INT2FLOAT(X)),
  RuleUnsigned2Float 双侧同 fire(367e R8 路+36a0 RSI 路);
  RuleInt2FloatCollapse(ruleaction.cc:9834-9894,oppool1 @ coreaction.cc:5637)
  在 oracle 把 4B MULTIEQUAL@3594:501 折叠为 `INT2FLOAT(ZEXT(RSI))`,
  zext 尺寸 9=preferredZextSize(8)(typeop.cc:1891-1902,inSize≥8→inSize+1)。
- 9 字节 unique 之谜:`opcode_name[]` #60="BUILD"=CPUI_MULTIEQUAL、
  #61="DELAY_SLOT"=CPUI_INDIRECT(opcodes.cc 74 名表 vs opcodes.hh 枚举),
  投影 v1.2.1 用 get_opname → MULTIEQUAL 渲染为 BUILD(非真 BUILD op)。

## ③ 修复

**ruleaction.rs 为被占域(GETPARAM-OPPOOL-COUNT-0001 排队租约)→
登记不写**:
- `MYPROGRESS-ANDCOMMUTE-GATE-0001` (P1, OPEN)
- `MYPROGRESS-INT2FLOATCOLLAPSE-0001` (P1, OPEN)
两行已入 docs/TODO_BOARD.md SB 表(write-set/验收命令/Ghidra 行号齐)。

## 三门禁 + 双 MATCH 复验(@ 94f3bf58,非陈旧引用)

- curl E2E 124 fn: skeleton **2665**/defects **0**/numbering **0** == 基线
- httpd E2E 29 fn: skeleton **2331**/defects **0**/numbering **0** == 基线
- next_url 投影 **MATCH**(stage+snapshot identical)
- match_url 投影 **MATCH**(stage+snapshot identical)

## Phase 2 方法论第六次验证判定

方法论再次成立:双侧投影→bisect 首分歧(ord 28 oppool1)→六块 diff 全部
归因到 2 个 ruleaction 根因 + 1 组下游残差,证据链双侧同 seqnum/
同 @END 计数闭合。myprogress 是首个把首分歧落在"规则**多 fire**(D1)
而非缺 fire"的函数,登记项给出门条件逐行修复方向。

## 未决问题

1. D1 修复须按字面移植 cc:1566 `(fullmask<<sa)&&fullmask`(疑似 Ghidra
   笔误 `&&` vs `&`)——按字面还是语义?倾向字面(1:1),修复 lane 决断。
2. XMM1 族(367e,R8)双侧在 pass1 均未折叠(oracle 亦然),pass2(ord 34+)
   是否折叠未追——D2 修复后 bisect 自然揭示。
3. metadata 未钉 curl/myprogress 投影(capture 模式 sha 见上);正式
   fixture 入库归 root 集成阶段(机制 B2 惯例)。
4. 修复叠加后 myprogress 函数级 E2E 行差(当前 ~87,subfloat 车道口径)
   预期下降——归 D2(金 golden 的 `fVar10=(float)uVar8/(float)(…)` 直接受
   Int2FloatCollapse 影响);待修复 lane 实测。
