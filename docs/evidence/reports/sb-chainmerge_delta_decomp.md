# Lane EV — 停车链 httpd +314 缺口双基线分解（root 终裁数据）

- 日期: 2026-09-23 (Asia/Shanghai)
- 车道: sb-chainmerge（只读分析,未动 src,未提交）
- 对象: merged = **wt/chainmerge@736982f2** 的 httpd 输出（canon 门禁 2539/0/0）
  vs master = **983e0fc9** 的 httpd 输出（2225/0/0）,delta = **+314**
- 基线: canonical = `tests/golden/ghidra_httpd_1204.c`（门禁准绳）;
  direct = `tests/golden/ghidra_httpd_1204.direct-runner.c`（EG2 裁定库级真值）
- 工件: merged/master 输出复用 EQ2 归档（`eq2_httpd.c`≡`eq2_httpd_r2.c` 已 cmp,
  `master_httpd.c`）;归一化/diff 口径 = `tools/compare_ghidra.py` 原函数复用
- **自校验**: 逐函数 diff 计数精确复现两个 compare 工件（2539 / 2225 / +314 全对上）

## 1. 方法（判类口径）

对每函数取四份骨架（compare_ghidra.normalize_skeleton）,对 master→merged 做
unified diff,± 多重集相消（同文本删+加=搬移,不计）,净增 882 行 / 净删 498 行逐行判类:

| 类 | 判据 | 含义 |
|---|---|---|
| **BRIDGE** | 行 = direct 同函数骨架（精确文本） | 库级正确桥接层行（master 缺） |
| **CANON_FORM** | 行 = canonical 同函数骨架 | 合并改善行（合并=canonical 形,master 缺） |
| **CAST** | cast 归一化后 = 任一基线同函数形 | 同构形,cast 拼写差（记改善侧） |
| **OVER_*** | 上述形**超出基线多重数的多余份** | 过度物化（库级缺口侧） |
| **GAP_STRICT** | 同函数两基线连同构形皆无 | **库级真缺口** |
| NOISE_GONE | 净删行,两基线皆无（master 特有伪影） | 改善（向双基线靠近） |
| LOST_CANON/LOST_LIB | 净删行但 canonical/direct 有 | 回退侧（丢了基线形） |

## 2. 三分类总账（root 终裁输入）

| 分类 | 行数 | 说明 |
|---|---:|---|
| **桥接层行 X**（库级正确） | **178**（+10 OVER_BRIDGE 边缘） | 精确 = direct 同函数形;其中通用结构行 58,**强桥接内容行 120**（调用形/赋值形,direct golden 逐字有） |
| **库级真缺口 Y**（须修） | **656** = GAP_STRICT 566 + OVER_CAST 71 + OVER_CANON 9 + OVER_BRIDGE 10 | 其中 WARN 格式差 41（纯注释地址格式,非语义）+ 对右值赋值净 +7（缺陷级不可编译 C,**master 本就 19 处,merged 26 处=扩大非引入**,§4） |
| **合并改善行 Z** | **517** = CANON_FORM 34 + CAST 14 + NOISE_GONE 469 | NOISE_GONE=master 特有伪影被合并清除 |
| 回退删除（负改善） | 29 = LOST_CANON 22 + LOST_LIB 7 | 量小 |

附加硬数据——**对 direct 基线的总距离: merged 3104 vs master 2828（+276,更远）**。
即 +314 不是"弃 canonical 换库级真值"的位移: 改善函数对**双基线同时**变近
（ap_pregsub −40/−30, ap_update_vhost_from_headers −34/−8 等）,回退函数对
**双基线同时**变远（main +227/+223, ap_fini +106/+106）。

## 3. main 与 ap_fini 分列（两大缺口函数）

| 函数 | Δcan | BRIDGE | CANON | CAST | OVER(物化) | GAP | NOISE_GONE | LOST |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **main** | +223 | 52 | 7 | 7 | 80 | **197** | 113 | 1 |
| **ap_fini_vhost_config** | +106 | 26 | 13 | 0 | 4 | **104** | 81 | 6 |
| 其余 27 净增函数合计 | −15 | 100 | 14 | 7 | 6 | 265 | 275 | 22 |

### 3.1 main（+223）——**不是桥接层故事,是库级真缺口**

决定性事实:**两个基线的 main 都是干净形态**（canon 532 行 / direct 527 行骨架,
双基线 main 均 0 个 uRam/0 个 CONCAT/0 个 in_*）;而 master main 骨架仅 174 行
（远未完成）,merged main 403 行（完成但形态双缺）。main 的缺口族谱（GAP 197 + OVER 80）:

| 族 | 行数 | 形态 | 基线判定 |
|---|---:|---|---|
| 过度物化栈写 | 70 | `*(undefined8 *)((int *)V - LIT) = LIT;` 共 74 次,基线 cast 同构形仅 ~7 次 | **67 行纯过度物化**（puVar 物化域,GOLDEN-CONTRACT-PUSHABSORB 同域但基线多重数不支持豁免 74 次） |
| CONCAT 拼装 | 35 | `V = CONCAT44(...)`/`CONCAT71(Ram…,uRam…)` 字符串常量逐字节重组 | 族在语料其他函数存在（canon 40/direct 29）,**但 main 两个基线 0 个** → 库级常量折叠/字符串恢复缺口 |
| WARN 格式 | 31 | `Removing unreachable block(,2c07d)` vs 基线 `(ram,0x0012c463)` | 印刷层格式差（非语义,低风险） |
| RAM 裸全局 | 30 | `uRam00000000000a5b93` 直传调用 | direct 语料有族（iRam 671）但 **direct main 也是 0** → main 位置上双基线皆无 |
| EXTRAOUT 变体命名 | 28 | `extraout_var_00..12`（编号变体） | 基线形态是 `extraout_RDX/RDX_00/EDX/XMM…`（寄存器名）,变体命名不匹配 |
| in_ 参数寄存器 | 12 | `in_R8`×7、`in_RIP`×3 等 | 见 §4 族判定 |
| RVAL_ASSIGN | 2 | `*param_1 + 0xb = puVar7;` | **缺陷级**（§4） |
| 其他 | 74 | `V = *(V + LIT);`、`(uint8)V >> LIT` 截取、`apr_pool_destroy(*(V+LIT))` 参数形 | 栈槽物化/传播不完整 |

> 注: 族计数按"行×族"计,一行可属多族（如 `in_RIP` 行同时计 IN_ARGREG）,故各行数
> 之和（282）略大于 GAP 197 + OVER 80 = 277。

### 3.2 ap_fini_vhost_config（+106）——**部分族级桥接 + 部分真缺口**

direct 基线的 ap_fini **本身**就是库层形态（267 行骨架,iRam×8/extraout×11/iStack×16,
vs canon 211 行干净形态）。GAP 104 行两分:

- **~51 行族级与 direct 层同族**（RAWSTACK 15 + RAM 15 + EXTRAOUT 7 + 参数寄存器 in_ 非 RIP 14）:
  direct ap_fini 也用这些族,但精确形/多重数不匹配（保守计入缺口,判类上偏桥接灰区）;
  另有 CONCAT 8 行族在语料其他函数合法但 ap_fini 位置双基线 0。
- **~53 行 direct 侧亦无的形态**: `*(undefined8 **)(in_RIP + LIT)` 寻址 ×10（direct 全语料 0）、
  `long unique0x…` P-code unique 空间泄漏 ×4、ZSEXT ×4（direct 语料 0）、`unkbyte1` 类型、
  `V._8_8_`/`._0_8_` subpiece 拼写混杂、对右值赋值等。
- （族计数有跨族重叠,两分合计≈104）
- LOST 侧: 丢 `V = true/false`（canonical bool 恢复形）5 行 + `int8 V;` 1 行。

## 4. 横切族判定（全 29 函数 GAP 566 行的谱系）

| 族 | GAP 行数 | direct 语料 | canon 语料 | 判定 |
|---|---:|---|---|---|
| in_ 参数寄存器（RSI/RDI/RCX/RDX/RAX/R8/RSP + 32 位变体） | 158 记号 / 148 行 | **仅非参数寄存器**（in_FS/in_R10/in_R11/in_AL/in_R8D/in_XMM6/7） | 同左 | **参数寄存器 in_ 是基线从不发出的形态** → 参数恢复/输入挂接域库级缺口（EH ActionInputPrototype/BOOMATTR residual ① 同域）。记号分布: in_RDI 48/in_RSI 45/in_RCX 17/in_RDX 15/in_RAX 12/in_R8 8/in_RSP 7 |
| in_RIP | 21 | **全语料 0** | **全语料 0** | RIP 相对寻址基线从不以 in_RIP 命名 → CHAINMERGE-INRIP-PRINTFAMILY-0001 确认为库级缺口（非桥接伪影）;ap_fini ×10、main ×3 |
| RAM 裸全局 | 59 | 有（iRam 671 等,散在其他函数） | 无 | 族=库层世界观;但 main 位置上 direct 也是 0。字符串/全局常量域 |
| CONCAT | 48 | 有（29,散） | 有（40,散） | 族合法但 main/ap_fini 位置双基线 0 → 常量折叠缺口 |
| WARN 格式 | 41 | 有（44） | 有（6） | `(,2c07d)` vs `(ram,0x0012c463)` — 印刷层,非语义 |
| EXTRAOUT | 39 | 有（327,extraout_RDX 族） | 有（26） | 命名变体（extraout_var_NN）不匹配基线寄存器名 |
| RAWSTACK（iStack_/uStack_） | 36 | 有（1732/787） | 有（7/221） | 栈槽物化域 |
| ZSEXT | 22 | 0 | 有（1） | 库级罕见形态滥用 |
| BADTYPE/BADSPACEBASE | 9 | 有（5,仅 cast 用法） | 0 | 基线只做 cast,merged 当类型声明（`BADSPACEBASE *in_RSP;`） |
| **RVAL_ASSIGN** | 净 +7（GAP 8） | **全语料 0** | **全语料 0** | `*param_1 + 0xb = puVar7;`/`*in_RDI + 0 = '/';` 等对右值赋值,**不可编译 C**;**master 本就 19 处（含 `*in_register_00000038 + 0 = '/';`）,merged 26 处**=既有缺陷类被扩大,非合并新引入 |
| SUBPIECE | 4 | 有 | 有 | 拼写混杂 |

## 5. 对终裁的建议

1. **Y 大,不可整体豁免**: 严格口径库级缺口 656 行（剔除 WARN 41 格式差后仍 ~615）,
   占净增 882 行的 ~74%。EG2 双基线分层若成立,httpd +314 中可豁免的只有
   ~188 行（BRIDGE 178 + OVER_BRIDGE 10）;**main +223 在双基线下都是缺口**
   （两基线 main 干净、merged 更远离 direct 而非更近）,不能按"链侧 RC1-3+EH
   预期形态面"定性为良性桥接膨胀。
2. **但缺口高度族化、杠杆集中**（不是发散损坏）,建议并车附带 P1 修清单:
   - ① 参数寄存器 in_ 族 ~179 个记号（含 in_RIP 21）: param attach/输入传播域
   - ② 栈写/栈槽过度物化 ~110 行（OVER_CAST 71 + RAWSTACK 36）: puVar 物化/StackSolver 域
     （GOLDEN-CONTRACT-PUSHABSORB-0001 若裁"库级为准",也只覆盖 ~7/74 的多重数）
   - ③ 字符串/全局常量 CONCAT 拼装 ~48 行 + RAM 59 行: 常量折叠/字符串恢复域
   - ④ 对右值赋值净 +7 处（缺陷级不可编译 C;master 既有 19 处,与合并裁决解耦建议单独立修）
   - ⑤ WARN 注释格式 41 行: 印刷层低风险
   - ⑥ extraout 命名变体 39 行 + ap_fini unique/subpiece 域: BOOMATTR residual ① 族
3. **合并的改善是真实的**: NOISE_GONE 469 行 master 特有伪影被清除,10 净改函数对
   双基线同时变近,LOST 侧仅 29 行。curl 侧（EQ2 已证）零争议。
4. 综合: **条件可并与 EQ2 结论一致,但 httpd 侧"骨架差全部落在链侧已知开放域"的表述
   需收窄**——按双基线判类,链侧开放域中约 3/4 的净增行是库级真缺口而非桥接层形态;
   若 root 接受"缺口族登记后修"路径,上述 ①-⑥ 即修域清单。

## 6. 产物

- `delta_decomp.py`（判类脚本,复用 compare_ghidra 口径,自校验通过）
- `delta_decomp.detail.txt`（29 函数 × 10 类逐行台账,含族标注）
- 本报告 `delta_decomp.md`
