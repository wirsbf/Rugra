# Lane FA2 终报 — GETPARAM-SWITCHNORM-0001 (wt/switchnorm)

- worktree: /dev/shm/rugra-worktrees/switchnorm, branch wt/switchnorm
- commit: **4e79535d** (基 = 亲父 8be100d9,单 commit)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
  (投影 pin: sb-oracle/curl.getparameter.constprop.0 + next_url + match_url,
  sb-parseconfig/curl.parseconfig)
- 日期: 2026-09-23; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-switchnorm

## switchnorm 缺口一句话

缺口不是"缺 fire"而是**缺上报**:apply 体自 JUMPTABLE-TABLEAPI-0001 P0-A 起
已逐臂镜像 coreaction.cc:4548-4565,但 Rust Action trait 默认
`take_count_delta` 恒 0,`self.count` 无人读入 `state.count`(Ghidra
action.cc:319/327-329/361 读成员并 return count)→投影 result/count/apply
恒 0。修复 = 补 `take_count_delta` 覆盖(既有 16 覆盖同族适配,单 hunk 8 行)。
诊断实证(前会话遗留 RUGRA_DBG_SWITCHNORM 插桩,已删):ord155 时 1 表
recovered=true labelled=false addrs=88 + fold_in_guards=true = 恰 2 计数;
ord299/340 labelled+fold=false = 0,均与 oracle 一致。

## 前代中断现场处置

- dirty=coreaction.rs(DBG 插桩+take_count_delta 雏形,留用后清理插桩)/
  ruleaction.rs+datatype.rs(`[DBG] ptrarith` 探针,**两文件编译错误**且域外,
  EZ 交付物在链上未并)——后两者经存档(interrupted_full_diff.patch)后
  `git restore` 归零;本 commit 对 ruleaction/datatype 零改动,与 EZ 无重叠。
- 本 session 手动补记 Ghidra 读回执(.zcode/record_receipt.py:coreaction.cc
  4540-4570 + action.cc 295-375)。

## ord 新状态(核心验收)

- getparameter 投影首分歧 **155 → 186**(+31 stages)。
- ord155 `universal:fullloop:switchnorm` 逐字段
  `result=2 count=2 tests=0 apply=1` == oracle(ord299/340 同为 0,一致)。
- **新首分歧 ord186** = `universal:fullloop:mainloop:oppool2`,首现即该
  stage(两侧此前均无此 op,系 oppool2 内规则新建):switch 表寻址链常量对
  `4080:1c65 INT_ADD c:4f0` vs oracle `c:4e8` + `4080:1c66 CROSSBUILD(RSP)
  c:fb10(-0x4f0)` vs `c:fb18(-0x4e8)`——表基差 8。**pre-existing**(ET 基
  投影同值,被旧 155 掩蔽),登记 `GETPARAM-TABLEADDR-0001`(疑 jumptable/
  ruleaction 域,coreaction/blockaction 写域外,需 drill oppool2 规则分解)。
- 同族普查登记 `ACTION-COUNTHARVEST-FAMILY-0001`:
  ActionUnreachable/ActionMarkExplicit/ActionMarkImplied/
  ActionStructureTransform/ActionReturnSplit 的 `self.count +=` 同无收割
  (ActionDoNothing 经返回路径适配已覆盖,ord154 3/3/3==oracle 即证);
  当前三投影函数内 oracle 计数均 0 故不可观测,harvest 不可能翻转 MATCH。

## 三门禁 + 投影(基线=亲父 8be100d9,default 模式亲测)

| 门禁 | 数字 | 基线 | 判定 |
|---|---|---|---|
| curl E2E | **2511/0/0** | 2511/0/0 | PASS 逐字节==基线(flags=0→issue_warning 门卫短路+断位未设,count 收割文本零影响) |
| httpd E2E | **2282/0/0** | 2282/0/0 | PASS 逐字节==基线 |
| getparameter 投影 | 首分歧 155→186 | 155 | PASS(ord155 全字段==oracle) |
| next_url 投影 | **MATCH** | MATCH | PASS 保持 |
| match_url 投影 | **MATCH** | MATCH | PASS 保持 |
| parseconfig 投影 | **MATCH** | MATCH | PASS 保持 |
| --func getparameter | **729/0/0** | 729(=亲父值;ET 报 743 系 CR8 基) | PASS 方向保持 |
| coreaction 单测 | 58/58 | — | PASS |
| annotations/refs/evidence 门 | 全绿 | — | PASS(hook 亲跑) |

注:RUGRA_MIRROR=1 口径 curl skeleton=4088 系 mirror 契约读数
(GOLDEN-CONTRACT-PUSHABSORB-0001 域),三门禁以 default 模式为准(基线同口径)。

## 机制 C 声明

coreaction.rs=主管线 Action 白名单。commit 4e79535d 附 ## Alignment
Evidence(四类语义 4/4)+## Differential;**未附 Cross-Review: APPROVE,
待 root 派独立 reviewer 逐行读 cc:4548-4565+action.cc:298-362 复核后方可
并入 master**。复核重点:take_count_delta 的 mem::take 排空时点(每趟 apply
后)与 Ghidra status_start 清 0(下趟)的单趟等价性;unlabelled 臂与
foldInGuards 臂对同一表可各 +1 的两处累计点。

## 回收

- worktree 保持(待 root 集成);/dev/shm/rugra-targets/sb-switchnorm 保留
  (root 复验增量缓存)。
- /dev/shm/rugra-tests/sb-switchnorm/ 已自清探针噪声,保留:gp_clean /
  next_url / match_url / parseconfig 投影、curl_default.c / httpd_default.c
  E2E、interrupted_full_diff.patch(前代现场)、commitmsg.txt(root 集成后可扫)。
