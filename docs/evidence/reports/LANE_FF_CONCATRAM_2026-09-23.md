# LANE FF 终报 — CONCATRAM-0001（wt/concatram，2026-09-23）

- owner: sb-concatram@wt/concatram（fixer；基 wt/chainfix f8ee7548 = CR16 APPROVED 态）
- commit: **9e2524c5**（src 两件 + docs/api 两件；机制 A 4/4，annotations/refs/doc-sync/gate-health 全绿）
- oracle pin: e40ed130；CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-concatram

## 物化决策缺口（一句话）

EV ③ 族（CONCAT/RAM 字符串域 ~107 行）的根因不在 varmap/printc 的物化决策层，
而在 **iced lifter（仅 httpd 走此路径；curl 主路径 SLEIGH）的三处指令语义缺陷**：
① `lea reg,[rip+disp]` 把 iced 已解析的绝对目标（memory_displacement64）再叠
next_rip → Ram@目标+rip 全落镜像外（0x9a7e0+），字符串/符号查表永不命中，且
错误地址在 0xa5xxx-0xa6xxx 密集互相重叠触发别名拆分 → CONCAT53/35/71/17(Ram,Ram)
字节拼装物化；② `mov r32,X` 缺 ia.sinc check_*32_dest 零扩 → 调用点
CONCAT44(<garbage>,imm) 高半物化（extraout_var/uVar15 族）；③ 段绝对寻址
（mov rax,fs:[0x28]）丢段前缀折叠成裸 Ram@0x28。EH 参数恢复不是诱因
（新输入组合只是让既有缺陷路径更显形）。

## 修复面（9e2524c5）

1. x86_lift.rs lea 臂：displacement 直接作绝对地址；结果落 **Const 空间**
   （SLEIGH rrip `COPY const:8(abs)` 形态——Ram 位置 varnode 会被 varmap
   ADDRTIED 臂符号化为 uRam… 名阻断 printer Priority-0 符号/字符串叶）；
   尺寸随目的寄存器宽；`lea r32` 追加 INT_ZEXT(dst32→parent64)。
2. x86_lift.rs mov 臂：32 位 GPR 写后 INT_ZEXT(dst32→parent64)
   （emit_alu_tail 同款 parent64 zext 补齐）。
3. x86_64.rs extract_operands：base=None 且 segment_prefix()==FS/GS →
   fs_offset/gs_offset 假名 → x86-64.sla 空间基址寄存器（FS_OFFSET=0x110:8 /
   GS_OFFSET=0x118:8，probe 实测）→ `*(in_FS_OFFSET + 0x28)` 双基线形态。

## 族前后计数（httpd）

| 指标 | pre（f8ee7548） | post（9e2524c5） |
|---|---:|---:|
| CONCAT 记号 | 51（14 函数） | **2**（ap_fini 栈槽 CONCAT44(uStack,uStack)=栈物化域既有缺口） |
| [ui]Ram 记号 | 69 | **1**（uRam…a11b8=ap_server_argv0 真实 .data 全局，direct 语料同族合法） |
| canary Ram@0x28 | 10 | **0**（→ in_FS_OFFSET 形 ×17，双基线形态） |
| **httpd canon** | 2433/0/0 | **2250/0/0**（−183） |
| httpd direct（库级真值） | 3000 | **2711**（−289，逐函数零回退） |
| 距 master（2238） | 195 | **12** |

canon 逐函数：main 884→800、ap_fini_vhost_config 401→312、
ap_update_vhost_from_headers 178→169、ap_ht_time 75→70；
ap_getword 33→36（拓宽形 SEXT48(iVar2+1) 与 canon `(long)(iVar4+1)` 语义更近，
拼写差计入 skeleton）、ap_os_is_path_absolute 29→30（int8/undefined8 拼写差）。
direct 侧两函数零回退。

## 链态三门禁 + 投影

| 门禁 | pre | post | 判定 |
|---|---|---|---|
| httpd E2E canon | 2433/0/0 | **2250/0/0** | ✅ defects/numbering 0 |
| curl E2E canon | 2507/0/0 | **2507/0/0**（与 EY2 输出 cmp 字节恒等） | ✅ |
| gcc 审计 | curl 82/25；httpd 6/23 | curl 逐字同；**httpd 7/22**（+1 修复） | ✅ |
| 三投影 stage_bisect --v1 | MATCH×3 | **MATCH×3**（next_url/match_url/parseconfig.constprop.0 全重生成，非 META diff=0） | ✅ |
| cargo test --lib 串行 | 1658P/18F | **1658P/18F 逐名同集**（funcdata/heritage 预存） | ✅ |
| E2E 可复现性 | — | httpd 复跑 cmp 字节恒等 | ✅ |

## 机制 C 声明

改动域 = src/disasm/{x86_lift,x86_64}.rs（RUGRA-GLUE lifter 层），**不在核心算法
白名单**（heritage/jumptable/blockaction/condexe/varmap 核心/merge/主管线
Action/Rule）——按 AGENTS 机制 C 不强制 Cross-Review。varmap/printc/coreaction
零改动（写入域按归因落点移至 disasm 层，归因证据见上"物化决策缺口"）。
建议 root 集成时按惯例对 disasm 改动做一次独立走查（重点：Const vs Ram 空间
语义与 seed_global_struct_pointers 的 Const 匹配、zext 对 prototype prepass
计数的影响——已实测 curl 输出字节恒等）。

## 相邻未动域（同根不同族，登记交接）

- `*(in_RIP + 0x<absolute>)` 形（INRIP 21 记号）：同根的**负载路径**变体
  （parse_operand 把 rip 基址保留为 in_RIP + 绝对目标），属已登记
  CHAINMERGE-INRIP-PRINTFAMILY-0001 域，修复形状不同（需 LOAD 直折 Ram@abs），
  本 lane 未触碰避免 write-set 冲突。
- 余 2 CONCAT44(uStack,uStack)＝栈物化域（EV ② 族，独立 lane）。

## 产物

/dev/shm/rugra-tests/sb-concatram/：httpd_ff3.c（=终态输出）、curl_ff.c、
ff.{next_url,match_url,parseconfig}.projection、commit_msg.txt、
test_ff_failures.txt、httpd_ff2.c（中间态，可回收）。
/dev/shm/rugra-targets/sb-concatram：留 root 集成后统一回收。
