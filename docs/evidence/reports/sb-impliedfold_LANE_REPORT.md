# MERGE-COPYNOISE-IMPLIEDFOLD lane 报告(wt/sb-impliedfold,自 master 3b97587a)

日期:2026-09-22。oracle:Ghidra 12.0.4 e40ed130(ghidra symlink HEAD 核对相等)。
commit:**1250e5d0** `fix: merge_test_with_list routes through precise HighIntersectTest (merge.cc:1664)`

## 1. CA 判决修正(机制断点一句话)

**断点不在打印侧**:Rugra `merge_test_with_list`(Merge::mergeTest port,
merge.cc:1657)绕过 testCache 用 `aggregate_high_cover`+`intersect_char>0`
粗近似(同块字符重叠 ⇒ 相交),而 oracle 走 `testCache.intersection`
(intersectList(…,2) + blockIntersection 实例时间戳级判定,
variable.cc:1166/998)。粗近似使 mergeOp Phase 2 对时间戳不交错的
MULTIEQUAL/INDIRECT 误判失败 → trim 循环(merge.cc:748-760)每个输入都
trimOpInput → **ActionMergeRequired 阶段 main +8804 op(oracle +45)**;
这些 trim COPY 被 MarkImplied 标 implied 后 mergeTestBasic 正确拒绝合并
(CA 测到的 1531 单侧 implied 正确语义),以 `uVarX = uVarX` 自赋值与
spill/restore 乒乓泄漏到打印。

打印侧一刀切折叠 in-implied COPY 是**错的**:oracle main 自己打印 20 个
合法 in-implied COPY(RHS 内联 CAST 表达式);printc.cc:2703-2705 只跳过
**out**-implied(Rugra printc.rs:3341 已有该跳过)。copynoise lane 的
"折叠责任在打印侧"推断被双侧实证推翻;COPYPROP lane 的"oracle 无
copyprop 规则"结论按错误名字搜索(RuleCopyPropagate vs 实际
**RulePropagateCopy**,ruleaction.cc:3924,oppool1 :5566,Rugra 已注册)。

## 2. 双侧实证方法(可复现)

- oracle 直连探针:`oracle_copyprobe_1204.cc`(本目录,git archive e40ed130
  + BfdArchitecture + Action::break_start 断点逐阶段 census)。产物:
  `oracle_main_copystate.log` / `oracle_main_stages.log` / `oracle_main.c`。
- Rugra 侧:curl_decompile RUGRA_DUMP_FUNC(临时加 flags/dead 字段,已还原)
  + RUGRA_STAGE_PROJ 节点轨迹 + coreaction 临时 COPYPROBE(已还原)。
- 关键数字对照(main):

| 切点 | oracle | Rugra(base) | Rugra(fix) |
|---|---|---|---|
| 管线入口 ops / COPY | 3022 / 726 | — | — |
| pre-assignhigh ops / COPY | 8904 / 190 | 8907 / — | — |
| mergerequired Δops | +45 | **+8809(main +8804,全语料 +13870)** | **+368 全语料** |
| MarkImplied imply 数(COPY 相关) | 22 | 大量(寄存器影子 120@r20a+137@r110 implied) | — |
| 终态存活 COPY | 234 | 9050 | **327** |
| 打印 COPY 语句 | ~185 | 608(336 out-exp/in-impl) | — |
| 自赋值 | 0 | 327(main)/907(全文件) | **2(main)/2(全文件)** |

## 3. 修复

`src/merge.rs` `merge_test_with_list`:`&self`→`&mut self`,粗近似换
`self.type_test_cache.intersection(other, high)`(Rugra 已有 HighIntersectTest
忠实 port:merge.rs:280 intersection + :140 block_intersection,mergeType/
mergeAddrTied 已在用),与 oracle merge.cc:1664 字面一致。

## 4. 三门禁(诚实 exit)

- curl E2E:skeleton **3654→3018**,defects=0,numbering=0
  (result/curl_cur.c vs tests/golden/ghidra_curl_1204.c,探针移除后构建
  byte-identical 复验)。
- httpd E2E:skeleton **2459→2406**,defects=0,numbering=0。
- cargo test --lib:merge:: 8/8,coreaction:: 57/57;全量 18 failed 为主仓
  d3fbe924 同基**预存在集合**(逐名核对一致,非本改动引入)。
- --func:main **1199→819**;glob_set 97→105(重排非缺陷,defects=0,
  距 golden 行 diff 114 vs 113,如实报告);match_url 86;gp 不在本语料。
- 自赋值计数:全文件 907→2(余 2 个 `glob = glob` 在 match_url,属既有
  PRINTC-CONDBLOCK-JUNKOPS-0001 junk-COPY 族,不在本 lane 修复面)。
- config 域零回退:未触碰任何配置/选项面。

## 5. B2 状态

`merge_test_with_list`(唯一行为改动函数):**NO_ORACLE**——无逐函数双侧
oracle fixture;证据=oracle 直连断点逐阶段 census(阶段级 MERGE-COPYNOISE
语义)+ 双语料 E2E 差分门禁(defects/numbering 全零)。
机制 C:`src/merge.rs` 在核心算法白名单——**本 commit 尚无独立 Cross-Review,
集成进主管线分支前必须由独立 agent 复核**(复核靶点:merge.cc:1657-1669
与 merge.rs:1775 对照,四类语义清单在 commit message Evidence 块)。

## 6. 文件清单(本目录)

- oracle_copyprobe_1204.cc / oracle_copyprobe(binary):oracle 直连探针。
- oracle_main_copystate.log:oracle main 终态逐 COPY 状态(234 条)。
- oracle_main_stages.log:oracle main 各阶段 census。
- rugra_main*.stderr*.log:Rugra main dump(base/fix1)。
- main_proj.txt:Rugra RUGRA_STAGE_PROJ 轨迹(299 snapshots,+8809 跳点定位)。
- mr_probe.log / mr_fix1.log:ActionMergeRequired 三步 COPYPROBE(base/fix)。
- curl_fix1.c / curl_final.c / httpd_fix1.c / httpd_final.c:修复前后输出。
- commit_msg.txt:提交 message 全文。

## 7. 移交主 agent

- TODO_BOARD 需更新:MERGE-COPYNOISE-DIFFHIGH-0001 / PRINTC-CONDBLOCK-
  JUNKOPS-0001 的"主杠杆=打印侧折叠"表述按本报告修正;余 2 个 match_url
  自赋值归 junk-COPY 族;COPYPROP_LANE_VERDICT_1204.md 的"oracle 无
  copyprop 规则"表述需勘误(RulePropagateCopy 存在,Rugra 已注册)。
- 机制 C 独立复核(集成前)。
