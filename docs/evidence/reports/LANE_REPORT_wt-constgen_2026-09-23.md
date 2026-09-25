# Lane ET 终报 — RANGEUTIL-CONSTGEN-0001 (wt/constgen)

- worktree: /dev/shm/rugra-worktrees/constgen, branch wt/constgen
- commits: **d626a117** (constraint family, rebase 于 CR8 **99f023f4** 之上;
  原始 daca9f9f) + **8c96a4ec** (docs/TODO); base = wt/vsempty@99f023f4
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
  (投影 pin: sb-oracle/curl.getparameter.constprop.0 / next_url / match_url,
  sb-parseconfig/curl.parseconfig)
- 日期: 2026-09-23; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-constgen

## 移植清单(全部对照 rangeutil.cc 锁定 oracle 逐行)

1. `CircleRange::pull_back(op, usenzmask)` cc:1022-1084 — op 级回拉:
   一元臂/二元非常量槽位臂/SUBPIECE nzmask 补救臂((msb(nzm)+8)/8 与
   outSize 比较+mask 扩展)/末尾 setNZMask 集交(2 段失败保留原范围仍算
   成功)。constMarkup 出参观测死(RUGRA-GLUE 省略,注释在案)。
2. `apply_constraints` cc:2105-2173 — boolean-flip 真假出边、
   restrictedByConditional 双侧、MULTIEQUAL landmark(addLandmark=equation@
   slot numParams)、descend 列表序遍历、read-site op-mark 旁路、
   MULTIEQUAL 真假块精确入边槽位限制、getImmedDom 支配链上溯。
3. `constraints_from_path` cc:2185-2203。
4. `constraints_from_cbranch` cc:2210-2238(双非常量输入→
   generateRelativeConstraint 提前返回)。
5. `generate_constraints` cc:2248-2307(系统块支配链收集,MULTIEQUAL 遍历
   全部入块;入边扫 2-out CBRANCH splitPoint;mark 去重清标)。
6. `generate_relative_constraint` cc:2351-2406(INT_LESS/LESSEQUAL→
   SLESS/SLESSEQUAL 重映射、checkRelativeConstant 两侧、COPY/PTRSUB/
   INT_ADD(常量 in1) 链回溯)。
7. 前置核实:FlowBlock 支配查询(getImmedDom/restrictedByConditional/
   getTrueOut/getFalseOut/block mark)block.rs 已齐备,零改动直接接线;
   block.rs 未动。
8. heritage.rs 仅 "Known residual" 注释同步(净行为零)。

## ord65 新状态(核心验收)

- **getparameter 投影首分歧 ord65 → ord155**(后移 90 stages)。
  ord65 `mainloop:stackstall:oppool1` count 738 vs 740 **解锁**
  (验收"740==740 或首分歧后移"以更强形式达成)。
- 新首分歧: `universal:fullloop:switchnorm` result/count oracle=2 vs
  rugra=0 (apply 1 vs 0) — 已登记 **GETPARAM-SWITCHNORM-0001** 待 root 派查
  (大概率 switch 归一化域,非 rangeutil)。
- "phi 左边界 −0x18" 验收点随 65..154 全 stage/snapshot 一致隐式解决。

## getparameter 方向

- E2E 文本 `--func getparameter`: 743/0/0 == 基线(投影推进未触文本层)。

## 三门禁 + 投影(基线=亲父 CR8 99f023f4 亲测)

| 门禁 | 数字 | 基线(CR8) | 判定 |
|---|---|---|---|
| curl E2E | **2559/0/0** | 2563/0/0 | PASS 硬门 0/0;-4=match_url EI +4 的四条栈声明(aiStackY_1040/iStackY_1038/aiStackY_1030/auStackY_102c)消失——golden 无此四行,match_url skeleton 58→54 **向 golden 收敛** |
| httpd E2E | **2333/0/0** | 2333/0/0 | PASS 字节恒等 |
| next_url 投影 | **MATCH** (335/96457) | MATCH | PASS 保持 |
| match_url 投影 | **MATCH** (340/80385) | MATCH | PASS 保持(E2E 的 −4 是非 mirror 模式 varmap 形态,投影流不受影响) |
| parseconfig 投影 | **MATCH** (335/130099) | MATCH | PASS 保持 |
| rangeutil 单测 | **54/54**(+3) | 51/51 | PASS |
| ruleaction 单测 | **210/210** | — | PASS(CR8 circleUnion 共测) |
| 全库 lib 测试 | 18 预存失败 | 与 CR8 基线**单线程逐字同结果** | 非本 write-set(funcdata::tests 对齐族+test_heritage_creation;并行批跑 23↔25 波动=既有噪声;root 可关注 wt/vsempty 侧 funcdata 族状态) |

新增测试: test_circle_range_pull_back_binary_less(真臂 [0,5)/slot 换位
[6,0)/双常量 None)、test_circle_range_pull_back_subpiece_salvage(无
usenzmask 失败/补救+8 字节 mask+nzm 集交)、test_generate_constraints_
true_branch_equation(四块图 CBRANCH 真块 LOAD 读点方程 [0,5)@4 全链 +
solve 后读范围收窄)。

## B2 / RAM 盘约定

函数级 fixture 未入库(root 集成阶段挑拣);投影/日志证据保留在
/dev/shm/rugra-tests/sb-constgen/ 直至 root 集成后清扫。

## 机制 C 复核请求(主管线 Rule 依赖面)

rangeutil 约束族属核心算法白名单。commit d626a117 带 ## Alignment
Evidence(apply_constraints/pull_back/generate_relative_constraint 三块,
四类语义 4/4 勾选)。请独立 reviewer 逐行读 cc:1022/2105/2185/2210/2248/
2351 后复核,重点:
- pullBack SUBPIECE 补救臂的 (msb+8)/8 整除与 outSize 比较;
- applyConstraints MULTIEQUAL 真假块精确入边(getIn(slot)==splitPoint)
  与 restrictedByConditional 短路顺序;
- generateConstraints 的 mark 双用途(blockList 收集期/ finalList splitPoint
  去重期)与清标时点;
- constraintsFromCBranch 双非常量输入→generateRelativeConstraint 的
  提前 return 点。

## 回收

- /dev/shm/rugra-worktrees/constgen-base(对照基线 worktree)已删;
  /dev/shm/rugra-targets/sb-constgen-base 已删。
- sb-constgen 产物(投影×4+bisect+E2E 日志+失败清单对照)保留至 root 集成。
