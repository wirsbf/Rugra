# Lane EG — GOLDEN-CONTRACT-PUSHABSORB-0001 量化裁决前置(双基线差分报告)

- 分支: wt/goldenct@**5e93d30b**(基 master bf3f5064;commit 内容 = 本 lane 全部写域产物)
- Oracle: Ghidra 12.0.4 e40ed130;x86:LE:64:default / gcc
- Rugra: bf3f5064 release,RUGRA_MIRROR=1,CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-goldenct
- 权威报告: `docs/alignment_docs/GOLDEN_CONTRACT_QUANT_2026-09-23.md`(commit 5e93d30b)
- 工件: /dev/shm/rugra-tests/sb-goldenct/{bridge_gap2,threeway,consensus}.py + .json
  ⚠️ 该目录 13:07-13:09 起出现并发写者(rugra_httpd_full*/rugra_curl_v2*,非本 lane),
  本 lane 文件名互不重叠,未受污染;清扫时注意区分。

## 1. 任务① — curl direct-runner golden:已存在且完整
- `tests/golden/ghidra_curl_1204.direct-runner.c` 于 0c912e90(2026-08-15)入库,
  sha256=56d0d317… 与 provenance 一致;输入指纹 8af50bca…=当前 examples/curl;
  oracle 同 e40ed130 同 arch/cspec;2026-08-25 MAINDIFF-DEADSTORE-0001 第三方活性复现
  (字节一致)。**无需重生成**,本 lane 补完整性复核+量化。
- oracle 环境:/tmp/rugra-ghidra-bfd-2.38 在(direct 可重建);
  /tmp/rugra-ghidra-1204-headless 已失(canonical dist,~40min 可重建)。

## 2. 任务② — canonical vs direct-runner(桥接层缺口)
| 语料 | 匹配 | 有差 | 总行 | push 族行 | 去 push 残差 |
|---|---|---|---|---|---|
| curl | 74 | 69 | 3979 | 462(11.6%) | 3525 |
| httpd | 790 | 787 | 38060 | 4973(13.1%) | 33199 |

- **0 纯 push 函数**;~87% 缺口=无 Java 分析器轴(xunknown 原型 20/74、424/790;
  类型/jumptable/DAT_ 符号)。
- DP 判决方向成立(direct xStack 490/5310 token vs canon 0/0;
  `xStack_50 = 0x2cffb;` 实证),量级=少数(12-13%)。

## 3. 任务③ — Rugra 三方读数(bf3f5064)
| 语料×基线 | matched | skeleton | defects | numbering |
|---|---|---|---|---|
| curl×canonical | 124 | 4091 | 0 | 0 |
| curl×direct | 117 | 3171 | 0 | 0 |
| httpd29×canonical | 29 | 4263 | 0 | 0 |
| httpd29×direct | 29 | 4646 | 0 | 0 |
| httpd840 部分×canonical | 224 | 18367 | 0 | 4(main) |
| httpd840 部分×direct | 224 | 19756 | 0 | 4 |

共识七桶(curl N=117 / httpd29 N=29 / httpd840 N=224):
- agree_all 832/507/2308;R_eq_D_not_C 975/390/1326;R_eq_C_not_D 312/46/158
- **C_eq_D_not_R(真缺陷方向)45/476/2106**;R_only 1084/2275/9866;
  C_only 1347/742/3851;D_only 1266/1099/5444
- push 赦免:Rc −12.4%(curl)/−1.4%/−2.8%
- curl 43 个 canonical-精确函数**全部** halt_baddata PLT 族;纯桥接仅 main_free;
  push 存储语句 Rugra 252 vs direct 218 vs canon 6(族级同形,+34 超出)

## 4. 任务④ — 裁决建议:**双基线分层门禁**
L0 完整性前置 → L1 双基线 defects/numbering 硬零 → L2 canonical 骨架预算
(+push 赦免桶,Rc_mod_push 为趋势)→ L3 库级子集交叉核对(C_eq_D_not_R 单调不增)。
否决库级单轨(覆盖 59.7%/39.3% + 惩罚已建成桥接建模 312 行/43 函数);
否决 canonical 单轨(C_only 1347/3851 永久留账 + 无契约独立交叉验证)。

## 5. 未决移交
1. HTTPD840-SEGV:master bf3f5064 MAX_FUNCS=840 第 227 函数 ap_core_input_filter
   SEGFAULT(rc=139);29/226 语料不触发。
2. MASTER-SKELETON-DRIFT:curl 2585→4091、httpd29 2333→4263
   (6b4ca15a→bf3f5064,11 commits;候选 56f88fb2/0a097498/cast 通道)。
3. numbering 语料序依赖:httpd main 29 语料=0 / 840 语料=4。
4. GOLDEN-CONTRACT-PUSHABSORB-0001 裁决本体(root 三选一)。
