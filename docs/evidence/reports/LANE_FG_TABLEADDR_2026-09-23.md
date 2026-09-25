# Lane FG 终报 — GETPARAM-TABLEADDR-0001 (wt/tableaddr)

- worktree: /dev/shm/rugra-worktrees/tableaddr, branch wt/tableaddr
- 基线: master **d8da9832**(亲父,三门禁 2381/0/0 + 2238/0/0 亲测口径)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
  (投影 pin: sb-oracle/curl.getparameter.constprop.0.oracle.projection)
- 日期: 2026-09-23; commit **05a0f6fc**(docs-only,单 commit,基 d8da9832);CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-tableaddr
- 交付形态: **零 src 改动的归因车道**(ruleaction.rs=FC 租约域,按派单"归因到彼则登记不写")

## 差 8 根因(一句话)

ord186 的 `0x4f0/-0x4f0 vs 0x4e8/-0x4e8` 与 jumptable 无关——它是
`oppool2:pushptr→ptrarith`(RulePtrArith→AddTreeState::calcSubtype,
ruleaction.cc:6252-6337)对栈数组寻址链做**数组基址吸附**时的 `extra` 常量差:
Ghidra 在 arrayHint≠0 时经 `hasMatchingSubType`(ruleaction.cc:6064-6107)→
`TypeSpacebase::nearestArrayedComponentBackward/Forward`(type.cc:3020-3037/2971-3018)
查询 ScopeLocal 中间符号图(restructureVarnode 产物),对 `aliases[].letter`
链(常量 -0x4f0 = raw 0xd8)向后命中 8B 非数组标量被拒、**向前**吸附到 -0x4e8
数组符号(extra=-8 → PTRSUB(RSP,-0x4e8) + 修正 INT_ADD #0x4e8);Rugra 的
calc_subtype Spacebase 臂只建模 arrayHint==0 的 getSubType 直查(extra 恒 0 →
-0x4f0),且 TypeSpacebase 的 scope 在 typefactory.rs:1958-1968 构造时被快照成
全局 scope 克隆(getMap type.cc:2935-2945 对 localframe 应动态解析
queryFunction(localframe)→fd->getScopeLocal()),栈偏移查询全部 miss。

## 证据链(全部本 lane 亲测)

1. **复现**: RUGRA_MIRROR=1 RUGRA_STAGE_PROJ/DRILL=1
   RUGRA_STAGE_FUNC=getparameter.constprop.0,
   `stage_bisect.py --v1` 首分歧=**ord186** `universal:fullloop:mainloop:oppool2`
   快照 op 索引 367,无 op 错位(371 stages 两侧同,ops 913373 vs 913079)。
   - oracle: `4080:1c65 INT_ADD in=c:4e8,…` + `4080:1c66 CROSSBUILD(opcodes.cc:46
     即 CPUI_PTRSUB 显示名) in=n:register:20,c:fffffffffffffb18`
   - rugra : `c:4f0` + `c:fffffffffffffb10`(终地址两侧恒等,纯中间分解差)
2. **drill 产生链**(双侧 drill,DEBUG 计数 3295-3303 全对齐):
   - pushptr(DEBUG 3299): `165: aa00 = a700(=RSP-0x4f0) + RAX` →
     `1c64: u1000052f = RAX + (-0x4f0)`,**双侧相同**;
   - ptrarith(DEBUG 3300): 建 1c65/1c66/1c67 三 op——常量对分歧唯一所在;
   - RAX 定义= `0x3fa1:8a: RAX = idx << 4`(16B 表步长,表=getparameter 的
     LongShort aliases[50],golden cc 1651 起)。三成员:raw 0xd0=lname(-0x4f8)/
     0xd8=letter(-0x4f0)/0xe0=extraparam(-0x4e8)。
3. **同族三位点对照**(oracle bs_probe2_oracle.drill vs rugra drill):
   | 位点 | 链常量 | oracle 吸附 | rugra 结果 | 判定 |
   |---|---|---|---|---|
   | 0x4088 lname | -0x4f8 | backward 数组命中 extra=0 → -0x4f8 | -0x4f8 | 巧合一致 |
   | 0x4080 letter | -0x4f0 | **forward** 吸附 extra=-8 → -0x4e8 | -0x4f0 | **分歧** |
   | 0x3fab extraparam | -0x4e8 | backward 数组命中 extra=0 → -0x4e8 | -0x4e8 | 巧合一致 |
4. **oracle 中间符号图反推**(由三行为唯一解):
   oppool2 时点 ScopeLocal = `[8B 单元素数组@-0x4f8][8B 标量@-0x4f0][数组@-0x4e8]`
   ——0x4f0 查询的 forward walk 要求 nextAddr=容器末=-0x4e8 恰命中数组首。
5. **探针实证**(临时 RUGRA_DBG_TABLEADDR,已还原,git diff 空):rugra 侧
   calc_subtype Spacebase 臂在 oppool2 时点对 -0xa78/-0x4f8/-0x4f0/-0x4e8 四个
   查询全部返回 miss(Unknown,extra=0)——scope 未接 ScopeLocal 或查询落全局克隆。
6. **Ghidra 语义复核**:TypeSpacebase 构造 `Datatype(0,1,TYPE_SPACEBASE)`
   (type.hh:735)→ size=0/alignSize=0 → AddTreeState size==0 → offset 保链常量、
   全部常量非倍数(multsum=0,无 PTRADD)——与双侧观测输出形态吻合;
   buildExtra 修正常量 = uintb_negate(correct-1) = -correct → +0x4e8 ✓。

## 修复三件(移交 FC,RULEARITH-SPACEBASE-ARRAYSNAP-0001)

1. `src/type_system/datatype.rs`: 补 TypeSpacebase::nearest_arrayed_component_
   forward/backward(scope.queryContainer 版;注意 ruleaction.rs:15088-15179 已有
   RulePtrsubUndo 的**结构体字段版**同名函数,勿混淆;forward 的三分支:
   `smallest->getOffset()!=0→nextAddr=addr+32` / `nextAddr=容器末` / wrap 检查;
   elSize=数组基元素尺寸)。
2. `src/ruleaction.rs`: calc_subtype Spacebase(+Struct)臂接 hint≠0 路径
   (biggestNonMultCoeff 传递;distAfter<distBefore,tie→backward)。
3. `src/type_system/typefactory.rs`(或 database.rs): getMap 动态化——
   localframe 有效时解析 fd ScopeLocal;构造期快照克隆必须消灭
   (restructureVarnode 建图发生在管线内、oppool2 之前)。

验收:gp 双投影首分歧 186 后移或 MATCH;--func getparameter 文本方向
(基线 729/0/0,golden=aliases[i].member 形态);三门禁+三投影 MATCH 保持;
机制 B2 fixture 钉三分支(向前吸附/向后命中/miss 兜底)。

## ord 新状态

- getparameter 投影首分歧 **186**(=FA2 switchnorm 修复后的既达状态;本 lane
  未改 src,无后移)——根因已从"疑 jumptable 表基址计算"更正为
  "ptrarith 栈数组吸附(hasMatchingSubType)+spacebase scope 未接 ScopeLocal"。
- jumptable 域随本归因**释放**(jumptable.cc 与 ord186 无关;投影快照中的
  CROSSBUILD 显示名=CPUI_PTRSUB,非跳表恢复 CROSSBUILD 语义)。

## 三门禁 + 投影(零 src delta,结构性继承)

| 门禁 | 数字 | 说明 |
|---|---|---|
| curl E2E | 2381/0/0(亲父 d8da9832 亲测) | 本 lane `git diff` 空→字节恒等继承 |
| httpd E2E | 2238/0/0(同上) | 同上 |
| gp 投影 | 首分歧 186(复现=基线,未动) | 本 worktree 亲跑 bisect 输出归档 |
| next_url/match_url/parseconfig | MATCH 继承 | 零 src delta |

注:gp_base 双投影/drill/探针实证归档 /dev/shm/rugra-tests/sb-tableaddr/。

## 机制 C 声明

jumptable.rs/heritage.rs **零触及**(归因证伪车道假设后按派单登记不写);
ruleaction.rs 仅有临时探针(已还原,commit 前 git diff 空)。无核心算法白名单
改动,无 Cross-Review 需求;修复三件移交 FC 认领(其 commit 按白名单自负
机制 A/C 责任)。

## 回收

- worktree 保持(仅 docs commit,待 root 集成);/dev/shm/rugra-targets/sb-tableaddr
  保留(root 复验增量缓存)。
- /dev/shm/rugra-tests/sb-tableaddr/ 保留结论件:gp_base.rugra.projection/
  gp_base.rugra.drill/ord186_bisect.txt/probe_run.stderr(探针实证)/
  探针还原后 diff 证明;probe/ 临时 cargo 工程已删。
