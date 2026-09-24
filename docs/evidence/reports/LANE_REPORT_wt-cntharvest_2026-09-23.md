# Lane FD 终报 — ACTION-COUNTHARVEST-FAMILY-0001 (wt/cntharvest)

- worktree: /dev/shm/rugra-worktrees/cntharvest, branch wt/cntharvest
- commit: **8080b430**(基 = 亲父 c790ae1b,单 commit)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
  (投影 pin: sb-oracle/curl.getparameter.constprop.0 + next_url + match_url,
  sb-parseconfig/curl.parseconfig)
- 日期: 2026-09-23; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-cntharvest

## 一句话

FA2 普查的五个"member count 无收割"残差,逐一对照 oracle 后**按各自真实形态**
落地——并非任务假设的五件同形横切:一件纯增覆盖、三件双桥收敛、一件自增删除。
全 A/B 零观测差(双 E2E + 四投影与基线逐字节 cmp 恒等)。

## 核心发现(与任务/CR15 前提的两处出入)

1. **三件已是"双桥并存"而非"无覆盖"**:ActionMarkExplicit/ActionMarkImplied/
   ActionReturnSplit 此前"member+=N 且 Ok(N) 返回"——Rust perform 的两条 count 桥
   (action.rs:338 take_count_delta 收割 + :344 正返回并入)是**相加**关系,返回
   路径已把 N 正确计入 ActionState(投影字段本就正确),member 是死重复。照 FA2
   模板直接加 take_count_delta 会**双计**。正典收敛:apply 恒 return 0(Ghidra
   cc:3271/3454/2323 形态)+take_count_delta 单桥;state.count 数学恒等
   (旧=返回 N+收割 0,新=收割 N+返回 0)。
2. **ActionStructureTransform 的普查前提不成立**:实际定义在 **blockaction.cc:
   2110-2115**(非 coreaction.cc),且 oracle apply 从不碰 count(函数体仅
   finalTransform+return 0,零计数点)。Rugra :15432 的 self.count+=1 系自创
   累计——TODO 行"harvest 后不可能翻转 MATCH"的论证对此件恰好失效(oracle
   count 结构性恒 0,收割非零值不需要快照先行分歧即可翻转 MATCH)。按铁律 1.5
   删除自创增量,member 恒 0=oracle,不加收割;测试改由 for_init/for_iter+
   NONPRINTING 见证。
3. ActionUnreachable(cc:3457)为唯一纯增件:FA2 同款 take_count_delta(mem::take)。

## 五件覆盖清单(oracle 累计点 → Rugra 处置)

| Action | oracle 累计点 | Rugra 处置(coreaction.rs) | 投影 count |
|---|---|---|---|
| ActionUnreachable | cc:3461(删块真值+1),return 0 | +take_count_delta(:3054) | 0→0(潜伏,fire 时=oracle) |
| ActionMarkExplicit | cc:3252 每 setExplicit+1;cc:3262 +=multipleInteraction;cc:3271 return 0 | 双桥收敛:apply 尾(:4470)恒 Ok(0)+take_count_delta(:4477) | gp2277/nu104/mu77/pc251 不变 |
| ActionMarkImplied | cc:3434 每完成判定 varnode+1;cc:3454 return 0 | 双桥收敛(:4742/:4748) | 98/83/54/36 不变 |
| ActionStructureTransform | **无**(blockaction.cc:2110-2115 零计数点) | 删除自创 self.count+=1(:15442) | 0=oracle 恒 |
| ActionReturnSplit | blockaction.cc:2317 每 nodeSplit+1;cc:2323 return 0 | 双桥收敛(:15816/:15833) | 0→0(潜伏) |

## 三门禁 + 四投影(基线=亲父 c790ae1b 本 worktree 亲测,A/B 逐字节 cmp)

| 门禁 | 数字 | 基线 | 判定 |
|---|---|---|---|
| curl E2E | **2511/0/0** | 2511/0/0 | PASS 逐字节==基线 |
| httpd E2E | **2282/0/0** | 2282/0/0 | PASS 逐字节==基线 |
| getparameter 投影 | 首分歧 ord186 | 186 | PASS 不变(GETPARAM-TABLEADDR-0001 pre-existing) |
| next_url 投影 | **MATCH** | MATCH | PASS 保持 |
| match_url 投影 | **MATCH** | MATCH | PASS 保持 |
| parseconfig 投影 | **MATCH** | MATCH | PASS 保持 |
| 五 Action count 字段 | 四投影前后 diff 全空 | — | PASS(桥收敛恒等实证) |
| coreaction 单测 | 58/58 | — | PASS |
| annotations/refs/evidence | 全绿 | — | PASS(hook 亲跑) |

注:gp 投影 markexplicit 2277 vs oracle 2275、markimplied 98 vs 100 为 ord186
先行分歧的下游快照差(pre-existing),本 commit 前后逐字节不变。

## 机制 C 声明

coreaction.rs=主管线 Action 白名单。commit 8080b430 附 ## Alignment Evidence
(四类语义 4/4,六个 Ghidra 函数逐行摘录)+## Differential;**未附
Cross-Review: APPROVE,待 root 派独立 reviewer 复核后方可并入 master**。
复核重点:①MarkExplicit/MarkImplied/ReturnSplit 桥收敛的 state.count 恒等性
(action.rs:338/344 相加关系);②StructureTransform 零计数点方向正确性
(blockaction.cc:2110-2115);③take_count_delta 排空时点与 Ghidra status_start
清 0 的单趟等价性(同 FA2 已批先例)。

## 回收

- worktree 保持(待 root 集成);/dev/shm/rugra-targets/sb-cntharvest 保留
  (root 复验增量缓存)。
- /dev/shm/rugra-tests/sb-cntharvest/ 保留:baseline_*/after_* 全套 A/B 产物
  (双 E2E .c+.stderr、四投影、run_gates.sh 可复现)、commitmsg.txt、
  baseline_run.log/after_run.log(root 集成后可扫)。
- 无探针插桩、无临时 DBG,src 与 commit 8080b430 一致;result/curl_cur.c 已回流。
