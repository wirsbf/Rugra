# Lane GK (wt/spindex) 终报 — SP 下标族 ruleaction 环节

- 基线：master 75b5d18f 亲测（httpd 1698/0/0，curl 1744/0/0）
- commit：**bda211ed**（wt/spindex）
- write-set 实际触碰：`src/ruleaction.rs`（一处比较）+ `docs/api/ruleaction.md` + `docs/TODO_BOARD.md`（3 行）+ `docs/alignment_docs/MAIN_RESID_ATTRIBUTION_2026-09-24.md`（§7）；varmap.rs/coreaction.rs 仅临时探针，已全部还原（git diff 空）。

## 两环节缺口定性（GI2 归因的裁决）

1. **ruleaction 环节（本 lane 修复）**：`AddTreeState::calc_subtype` 头部
   `tmpoff < size` 被 Rust 化成有符号比较，负偏移（向下生长栈 SP-alias，
   tmpoff=0xfff..f8）误入 `offset=tmpoff` 分支 → multsum 清零 →
   `valid=false` → INT_ADD→PTRADD 改写对整族不触发。Ghidra
   ruleaction.cc:6256 是 uint8×int4 → 无符号比较（模除路径保 multsum →
   PTRADD 生成）。修复一行。
2. **varmap 环节（未动，登记移交）**：SP-alias 栈符号类型固定点——
   restructure 终态 `undefined1[32] auStack_c8`（oracle `long local_c8[4]`）
   且 open-hint 自举循环（alias 基类型恒 ptr->undefined1=符号自身元素
   类型）；pass2+ 丢失 -0xd0/-0xd8 alias → local_d0/local_d8 符号缺失。
   登记 `VARMAP-SPALIAS-RETYPE-0001` +
   `RULEACTION-SPALIAS-INDIRECTPTR-0002`（含探针数据与调查入口）。

## 族计数（httpd main）

- SP-cast 形 `*(undefined8 *)((int *)puVar10 - 8)`：**101 → 40**
- 下标形 `puVar10[-1]`：**33 → 94**（oracle 下标形 180；canon 136/direct 152）
- main skeleton：**715 → 645**

## 三门禁（亲父 75b5d18f 亲测基线对照）

| 门禁 | 基线 | 交付 | 判 |
|---|---|---|---|
| curl E2E canon | 1744/0/0 | **1745/0/0** | +1=main 413→414（破损 for 单行变 oracle 同构 while 两行，Differential 已解释） |
| httpd E2E canon | 1698/0/0 | **1628/0/0** | main -70，零回退 |
| gcc 审计 | curl 104/20, httpd 21/8 | 逐函数相同 | 零新增失败 |
| 五投影 | MATCH ×5 | **MATCH ×5**（逐字节，仅 META 头） | 保持 |
| 逐函数 | — | curl 仅 main +1 / httpd 仅 main -70，余全平 | 零回退 |
| B2 fixture | ptrarith_addtree 5 用例 | 双侧重跑 **MATCH**（host-compiler pin 漂移为亲父环境缺口，scratch 仅豁免身份钉） | 保持 |

单测：ruleaction 218/218、varmap 45/45、printc 12/12。

## 机制 C 复核请求（ruleaction 白名单）

请独立复核者自读 Ghidra ruleaction.cc:6252-6276（calcSubtype）与
Rugra src/ruleaction.rs calc_subtype（18517 起），复核点：
① cc:6256 `uint8 tmpoff < int4 size` 的 C++ 常规算术转换（int4→uint8，
无符号比较）与 Rust `tmpoff < self.size as u64` 等价性；
② 正数域行为不变性（size 恒 ≥0 来源=byteToAddressInt(alignsize, ws)）；
③ 模除路径 multsum 重赋值 `multsum=(tmpoff-offset)&ptrmask` 在负偏移下
保留 0xfff..f8 的下游效果（buildMultiples constCoeff=-1 → PTRADD）。

## 产物

- 本目录：httpd_before/after.c、curl_after.c、perfunc 表、
  run_ptrarith_addtree_scratch.sh（B2 scratch 重跑脚本）
- /dev/shm/rugra-tests/sb-spindex/：五投影 rugra 侧产物（对照
  /dev/shm/rugra-tests/sb-oracle/ 的 oracle 钉板）
