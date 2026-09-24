# Lane EF 终报 — MERGE-COPYNOISE 残差族:main spill/restore 对(诊断深化,零 src 改动)

- worktree: /dev/shm/rugra-worktrees/copynoise(branch wt/copynoise,基线=亲父 663458e7,tree clean)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- 写域:src/merge.rs + docs/api/merge.md(本次零 src 改动,探针已全部回退并验证)
- 交付形态:根因定位记录(铁律 4 第 3 类),TODO 登记 MERGE-COPYNOISE-SPILLRESTORE-0001

## 症状(基线亲测,parent 663458e7)

`--func main` 残余 diff-high COPY 对(golden 无此形态):

- spill  @0x2669: `pFStack_240 = __stream;`(COPY s(stack:0xfffffffffffffdc0) = u(__stream:unique))
- restore @0x3188: `__stream = pFStack_240;`(COPY u(__stream:unique) = s(stack:…fdc0 经 MULTIEQUAL 45531))

机器码:0x2669 `mov %r14,0x18(%rsp)`(gcc 把 callee-saved r14 溢出到栈槽 -0x240)、
0x3180 `mov 0x18(%rsp),%r14`(loop 后重载)。计数:main spill/restore 栈槽对
Rugra=1 / golden=0(全语料同族:Rugra 4 / golden 5,其余 3+3 在 glob_word 双侧同现,非本族)。

## 根因一句话

**双侧 IR 完全同形(见下),分歧收敛在 mergecopy..mergetype 窗口对 (slot-high × __stream-high)
的合并判定:oracle 判"无交集"→合并→copymarker 按 markInternalCopies 同高内拷贝隐藏两 COPY;
Rugra 的 HighIntersectTest port 在块级测试返回 intersect=true(槽 INDIRECT/MULTIEQUAL 链版本 ×
R14-phi@0x2780 版本,blk29-53 区间 1041 对触发样本)→合并被拒→两 COPY 显式打印。**

## 双侧 IR 同形证据(排除上游域)

1. **折叠时机**:`RuleLoadVarnode`(ruleaction.cc:4290,stackvars 池)把 rsp+const LOAD/STORE
   折叠成栈 varnode COPY——双侧都在 stage 41→42 边界(constantptr 后、oppool2 入口)完成
   (双侧 stage 投影 SNAP41 raw STORE / SNAP42 slot-COPY 逐行同)。
2. **heritage 次数**:双侧 main 各 7 次 heritage(12/50/86/127/158/194/235)。
3. **INDIRECT 链**:oracle drill(/dev/shm/rugra-tests/sb-drill/curl.main.oracle.drill,5MB,
   本 lane 新捕获,sha e6e7be84…)含与 Rugra 完全同地址的槽 INDIRECT 链
   (0x25f2/0x2603/0x2767/0x3322/0x263b/0x3283/0x2653/0x26ce/0x31ff/0x26f2/0x278d/…)。
   ⚠ stage 投影(capture v1-no-OPACTION_DEBUG)对 MULTIEQUAL/INDIRECT 全程不可见(0 条),
   用它判"oracle 无链"会得出错误结论——已实测证伪。
4. **mergerequired trim**:oracle mergeOp(R14-phi@0x2780:18cd)phase-2 失败→trimOpInput 两槽边
   (0x3188:43b0/0x3198:43b1 两 trim COPY)+ stdin-INPUT 边 snipReads(0x25a4:438f u10000a41);
   Rugra 最终 IR 同形(phi@0x2780 = (56132,56132,56099),spill 输入=unique(stdin COPY out))。
5. **dominantcopy**:oracle 把 43b1 折叠进 43b0(direct COPY 销毁,phi 输入重定向);
   Rugra dump 同形(vn#56132 双槽位)。此后到 copymarker 双侧 IR 冻结。

## 分歧点(未钉死最后一环)

- Rugra 探针(已回退):mergecopy 对 (out=slot-high 142 实例, in=__stream-high 7 实例) 
  req_ok=true、intersect=true→merge 跳过。触发对类别:slot[MULTIEQUAL/INDIRECT@0x2780-block] ×
  Register:b0[MULTIEQUAL@0x2780](cover blk29-34 全块铺满,经 phi@0x27d0 edge-0=bb33 回溯,
  与 oracle drill 的 phi 读者结构 0x2728:18ca/0x27d0:18cc 同构——手工推导双侧 cover 应同形)。
- oracle 侧 mergecopy/mergeadjacent/mergetype drill 窗口均 empty=1(merge/high 标志不产生
  op 级 DEBUG 记录,无法直接观测决策);golden(main 无 pFStack_240 声明、无 restore 语句)
  证明 oracle 高层合并发生(否则 printc 必打独立槽变量声明)。
- 候选残差(下一步排查清单,按优先级):
  R1 testCache 缓存链:oracle mergerequired 阶段 mergeTest(R14-high×slot-high) 已测并缓存,
  trim 后 COVERDIRTY 失效/重算路径 vs Rugra 缓存写读时点(move_intersect_tests 搬移语义);
  R2 update_high/high.cover 新鲜度:Rugra inflate_test 读静态 high.cover(markimplied 时点
  探针实测 blocks=0 空 cover 场景存在),oracle 经 testCache.updateHigh 惰性重建;
  R3 block 级 pair 遍历的 gather_block_varnodes 过滤参数(aCover/bCover 传递序)逐行复核;
  R4 MERGE-UNTEDINTERSECT-0001(已登记的缺失回退臂)只增交集,不解释本症状,非本因。

## 门禁(基线=亲父 663458e7 亲测,本 lane 零 src 改动)

- 全语料 E2E:回退探针前后输出 byte-identical(cmp 通过)→亲父基线行为无扰动。
- --func main:defects=0 / numbering=0 / skeleton 583(含 EA 并入的 ~20 行 cast 形态互换,
  属预期,未误判;spill/restore 对为 skeleton 层差异,非 defects 计数项)。
- next_url/match_url/parseconfig 三投影:src 与亲父 git-diff 为空 + E2E 字节恒等 ⇒ 投影
  结构性继承亲父 MATCH;直接 stage_bisect 复跑被 META 身份键(load_mode=producer tree hash)
  抑制,证据 = git diff 空 + cmp 恒等(见上)。
- gcc 语法审计:同亲父(未重跑,src 未变)。

## CR2 条件② census 探针原始输出留档

- /dev/shm/rugra-tests/sb-copynoise/probe1_stderr.log(mergecopy 判定:142/7 实例、req_ok/intersect)
- /dev/shm/rugra-tests/sb-copynoise/probe2_stderr.log(触发对首览)
- /dev/shm/rugra-tests/sb-copynoise/probe3_stderr.log(1041 触发对 + 双方 cover 块明细)
- /dev/shm/rugra-tests/sb-copynoise/probe4_stderr.log(inflate_test 判定细节,含空 cover 场景)
- /dev/shm/rugra-tests/sb-drill/curl.main.oracle.drill(oracle main drill,5MB,本 lane 新证据)
- 内存盘易失;结论已固化至 docs/TODO_BOARD.md 的 MERGE-COPYNOISE-SPILLRESTORE-0001 行。

## 结论与移交

按铁律 1.4/机制 D,未钉死 oracle 块级判交为 false 的精确语义前,拒绝投机性放宽交集
(会引入行为分叉)。本 lane 移交:合并判定链的 R1-R3 排查(写域仍 merge.rs;
R2 需 coreaction markimplied 只读探针配合)。三门禁与基线恒等,无回归。
