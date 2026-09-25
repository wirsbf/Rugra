# Lane GF (widthop) 终报 — WIDTHOP 宽度算子族打印域批修

- worktree: /dev/shm/rugra-worktrees/widthop (wt/widthop), 基 = master b25bce7a
- commit: **867bce7a** (src/printc.rs + docs/api/printc.md + docs/TODO_BOARD.md)
- oracle: Ghidra 12.0.4 e40ed130; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-widthop

## 打印规则缺口（一句话）

Rugra printc 的三段式 SUBPIECE/ZEXT/SEXT 分发（opSubpiece/opIntZext/opIntSext 与 cast 判定
isSubpieceCast/isZextCast/isSextCast 的 Rust 镜像）本身无缺口；F 族根因是 **印前指针兜底盖章通道
把 8 字节 `int *` 无差别盖到扩展/截断输出上**——盖的是 Ghidra 明文禁止的 out→in 指针方向
（typeop.cc:1197；ZEXT/SEXT 无 propagateType 覆写、SUBPIECE 仅 far/near+getSubType），且按
(space,offset) 键匹配撞上寄存器 SSA 同键多代（RAX/EAX/AL 全 offset 0，一键 27+ 对象）——被盖
类型让三个 cast 判定全 false，三段式落 opFunc 兜底印出 `SUB81(x,0)`/`ZEXT48(x)`，而 oracle 同
位点印 `(char)x` cast / 隐没扩展。

## 修复

盖章域收缩（printc.rs:9029-9152）：仅直接 LOAD/STORE 地址槽 varnode（create_index 身份匹配，
指针按 propagateToPointer 尺寸对齐 typeop.cc:495-498）+ 尺寸 8 且 def ∉
{ZEXT,SEXT,SUBPIECE,PIECE,INSERT} 的加法输入；命名集合 pointer_varnodes（piVar 前缀）不动。

## 两亚族前后（token 计数 = 输出中 SUB8x/SUB4x/ZEXT/SEXT 显式算子）

| 语素 | 前 | 后 | 形态 |
|---|---|---|---|
| curl | 48 | 12 | `SUB81(pCVar17,0)`→`(char)` 类 cast/`(int*)` 等；`ZEXT18(*pattern)`→隐没（golden `(*V)[*pattern]` 同构）；`SEXT48(iVar14)`→隐没（golden `argv[iVar14]` 同构） |
| httpd | 50 | 16 | 同族（ap_getparents 的 `SEXT48((int)V)`→`(long)(int)` 类、`ZEXT18`→隐没为主） |

残余 12+16：①SUB out=undefined 基型（oracle 由 setcasts TypeOpSubpiece::getOutputToken 的 INT
基兜底 updateType 成 int/char）→ coreaction.rs FV2(81cdfa2b) 后继域，让渡；②ZEXT/SEXT out 落在
含真指针实例的合并 high（代表类型 int*）→ varmap/Merge 代表性类型域，新残差候选。均已登记
RESIDMAP-ZSEXT-WIDTH-OPS-0001。

## 三门禁（基线 = 亲父 b25bce7a 亲测）

| 门禁 | 基线 | 交付 | delta |
|---|---|---|---|
| curl E2E | 1995/0/0 | **1992/0/0** | −3（glob_range 69→67, file2string 113→112） |
| httpd E2E | 2072/0/0 | **2068/0/0** | −4（ap_getparents 109→105） |
| gcc 审计 | curl 104OK/20FAIL; httpd 8OK/21FAIL | 同基线逐字节 | 0 |

逐函数零回退（124+29 函数中仅上述 3 函数 diff 计数变化，全为下降）。
四投影 next_url/match_url/myprogress/parseconfig：stage 流与 MATCH 态逐字节恒等
（仅 META producer tree-id 行）。双跑字节恒等。cargo test --lib：失败集=已知 flaky 族
（base 轮 19/fix 轮 17，基线自身轮间漂移 19↔27），printc:: 12/12 + cast 20/20 全绿。

## 工件

curl_base/httpd_base.c（基线）、curl_final{,2}.c/httpd_final{,2}.c（交付+双跑）、
proj/*.rugra.projection（四投影）、failures_{base,fix}.txt（单测 A/B）、gp_probe*（探针过程件）。
