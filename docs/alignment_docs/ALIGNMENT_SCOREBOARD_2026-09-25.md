# Alignment Scoreboard — 2026-09-25（STAGE-BISECT-E2E 波次日）

> 事实源: 本文件为当日快照;持续账本见 `docs/TODO_BOARD.md`（活动）与 `CURRENT_STATUS.md`（默认脸数字）。
> 全部数字为 `compare_ghidra.py` 官方口径 vs 锁定 canon golden（12.0.4, e40ed130）;commit 可溯。

## 1. 语料收敛轨迹（骨架行 / defects / numbering 全零）

| 口径 | 波起点(09-24) | 当日终态 | 降幅 |
|---|---|---|---|
| curl 默认脸（全通道默认开） | 1329 →（本波）3718 为全管线裸口径 | **577**（cb759c42 亲验） | 全管线 −84.5% |
| httpd 默认脸 | 1445 | **≈1139**（1179−40 分量叠加;收官终验在跑） | −66%~−68% |
| 函数级全同 | curl 62 | **curl 107+/124（86.3%）**;httpd 11/34 | — |

默认脸构成（用户决策落地）: SYMDB+pretty emitter（DFLIP 791611bf）+ 种子三门（SEEDFLIP 2d88bbcb,opt-out 逃生门+mirror 恒裸+无 manifest 优雅 no-op=stripped 兼容）。

## 2. B2 投影银行

**391/391 MATCH**（当日 26 → 391）: ADDRARM2 地址臂解锁 curl 45 PLT thunk（全首验 MATCH）;HBANK+HBANK2 解锁 httpd 320 thunk（账本臂+批量入库,零分岔）。

## 3. 桥接通道账（HEADLESS-BRIDGE-V1）

| 通道 | 状态 | 关键证据 |
|---|---|---|
| C1 TYPESEED（committed local 类型/名字） | ✅ 双语料默认 | oracle 级预验证（锁定库真 localdb 链）;15 处 <retaddr> 拼写证 oracle 亦不可复现=超通道残差 |
| C2 DWARFSEED（.debug_info 语义名） | ✅ curl 默认（httpd stripped 无源,HSEED 机器判定） | 6 函数声明层逐名复现;11 不可复现归 C3/C4 |
| C4 STRUCTSEED（结构体复合） | ✅ curl 默认 | 三门 944→767 的主引擎;va_list 数组形运输判决 |
| C3 glob 载体 | ✅ 判决: 载体已在（原型锁定+参数符号） | 第 4 门实证有害拒绝（28→40）;残差定向 consume 域 |
| REGSYM（寄存器符号） | ✅ 判决: 载体已在 | `::` 域前缀杠杆 → SCOPEPFX 落地（curl −92） |
| 注释通道（sec_offset 族） | 🔓 解锁在望 | oracle 锚规则复现 45 行;阻塞=printc 两行（PRINTC-COMMENTFILL） |
| PIRAM | 🔄 在飞 | PDOTFORM 移交件 |

## 4. 判决级负结果（本波方法学核心资产）

ADD 6 例"假设被 oracle 仪器化证伪→真凶域外钉位"的判例: ADDRSLOT（coreaction 无罪→varmap）、AFINI（varmap 无罪→lifter/print/HEAD）、RANGEHINT（库真值与 Rugra 同形→HEAD）、RENUM（重编号级联=度量伪影,真偏号 0 行）、C3CONSUME（消费链 op 级同形→渲染/联合体域）、CURLSYM/REGSYM/C3GLOB（载体已在/通道惰性）。
**模式结论: 剩余残差主导域=canon 的 analyzeHeadless 桥接层,非库缺陷。**

## 5. 跨空间族四波歼灭（机制 C 全程）

XCORSS（push_multiequals+六 guard,−42 门控）→ OPZERO（op_zero_multi 同构）→ SPACEFIX（fspec dealloc+coreaction join 四分支）→ FAMAUDIT（transform/double_precis/pushmeq 比较）→ RUFOUR（ruleaction×4,在飞）。全部 CR APPROVE 或同构先例。

## 6. 结构化/物化/调用域

- JTRES: fused-dest 分裂+goto 臂（main −72）;CASEWRAP: isexit 时点+default 基本图路由（−25+curl 同步改善）——双 CR APPROVE
- GETPARAM: canary/counter/for-header 三根因（REJECT→六条件补齐→CR-R2 APPROVE 闭环——机制 C 纪律首例完整回路）
- ALIASGATE: isPossibleAlias 逐行移植（httpd −78 过度物化回收,CR APPROVE 无附带）
- MGENOISE: CALLIND 锚定重放（httpd −40,ap_vhost 51→9）;吸收缺口判"已闭环"

## 7. 在飞与队列

在飞: SHAPEFIX（物化形状域）/CSPEC2（调用规格消费者）/RUFOUR（第四波）/PIRAM。
队列: PRINTC-COMMENTFILL 两行解锁→注释通道 −45;SHAPEFIX 后 printc 域续（CAST+init-less 门）;V3/V4 余项;oracle 漂移重钉策略（12.0.4→12.1.4 待决）。
