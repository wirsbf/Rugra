# GOLDEN-CONTRACT-PUSHABSORB-0001 量化裁决报告:canonical(analyzeHeadless)vs direct-runner(库级)双基线

- 日期: 2026-09-23
- Lane: EG wt/goldenct(基 master `bf3f5064eaf89089732d40b7f45cf11679a51ea2`)
- Oracle: Ghidra 12.0.4,commit `e40ed13014025f82488b1f8f7bca566894ac376b`(tag Ghidra_12.0.4_build)
- 语料指纹(2026-09-23 重验,与两侧 golden provenance 逐字节一致):
  - `examples/curl` sha256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`
  - `examples/httpd` sha256 `805f89cdbdce827f8f6ccd877aa7c344ff1105713b7bf7b0e6f313affa93b1c1`
- Rugra 构建: bf3f5064,`cargo build --release --examples`,
  CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-goldenct(6m42s,rc=0)
- E2E 驱动: `RUGRA_MIRROR=1`(canonical 镜像态束,MIRROR-ENVS-CANONICAL-0001)
- 度量: `tools/compare_ghidra.py` 的 `normalize_skeleton` 骨架 diff(本报告脚本直接
  import 该模块,与差分门禁同源;±行计数,unified n=0)
- 工件: `/dev/shm/rugra-tests/sb-goldenct/`(bridge_gap2.py / threeway.py / consensus.py /
  *.json / rugra_{curl,httpd,httpd840}.c)

## 0. TL;DR(裁决建议 = 三选一中的"双基线分层门禁")

1. **curl direct-runner golden 已存在且完整**(2026-08-15 `0c912e90` 入库):sha256、
   输入指纹、oracle 血缘三重验证 + 2026-08-25 第三方活性复现,无需重生成。
2. **DP push 吸收判决:方向成立,量级修正**。canonical vs direct-runner 骨架差中
   push/extraout 族仅占 **11.6%(curl)/13.1%(httpd)** 行;**0 个函数**的桥接差是纯
   push 族。桥接层缺口的 ~87% 是"无 Java 分析器"环境差(原型/类型/jumptable/引用)。
3. **Rugra 不是"库级同形"的单纯受益者**:curl 侧 43 个骨架上与 canonical 完全一致
   的函数**全部**是 `halt_baddata` PLT/thunk 族(=驱动侧桥接输入建模的产物,
   direct-runner 契约里没有这形态);深度函数在双基线上都仍有差。
4. **双基线共识分解**:两 oracle 一致而 Rugra 不同(C_eq_D_not_R)= curl 45 行 /
   httpd(224 函数部分语料)2106 行 —— 唯一与契约无关的"真缺陷方向"信号;
   Rugra 自创行(R_only)占 canonical 残差 ~31%(curl)/~58%(httpd840)。
5. **推荐:双基线分层门禁**(§4)。单选库级=语料覆盖只有 59.7%/39.3% 且惩罚已建成
   的桥接建模;单选 canonical=C_only(analyzer 形态行)永久留在缺陷账上反复重讼。

## 1. 基线资产与完整性核查(任务①)

| 文件 | 函数 | 行数 | sha256(实测=provenance) |
|---|---|---|---|
| `tests/golden/ghidra_curl_1204.c`(canonical) | 124 | 3318 | `aca37988…` |
| `tests/golden/ghidra_curl_1204.direct-runner.c` | 74 | 3061 | `56d0d317…` |
| `tests/golden/ghidra_httpd_1204.c`(canonical) | 2010 | 66637 | `6b4c4f31…` |
| `tests/golden/ghidra_httpd_1204.direct-runner.c` | 790 | 37456 | `ead6e3bf…` |

- 生成管线(读 provenance + tools 复核):canonical = `tools/build_ghidra_1204_headless.sh`
  从锁定 e40ed130 源码构建 headless dist → `tools/regen_ghidra_golden.py` 驱动
  analyzeHeadless 默认分析 + decompile-all postScript(30s/函数,双跑 byte-identical)。
  direct-runner = 同一锁定 cpp 树 `make decomp_opt`
  (BFDHOME=/tmp/rugra-ghidra-bfd-2.38/usr)+ 内嵌 `golden_dump_1204.cc`
  driver(fixture sha `c82028e4…`):BFD 静态+动态符号表发现函数 + .rela.plt 解析,
  每函数独立 hermetic 进程,600s/函数;provenance 记 12 样本 byte-identical。
- 完整性:四文件 sha256 与各自 provenance 的 golden_sha256 一致(本 lane 实测);
  `input.sha256` 与当前 examples/{curl,httpd} 一致 → 无输入漂移。
- 活性再验证(历史):MAINDIFF-DEADSTORE-0001(2026-08-25)自建同版本 instrumented
  driver 直跑,输出与入库 direct-runner golden **字节一致**。
- **判定:curl direct-runner 无需重生成**。任务①的"复刻"已由 0c912e90 完成,本 lane
  补齐的是完整性/血缘复核 + 下文的量化。
- 登记差异:direct 函数发现=BFD 符号表(curl 74/124=59.7%,httpd 790/2010=39.3%),
  canonical 的分析器发现函数在 direct 侧结构性缺席(provenance equivalence_risks #1);
  剥 GCC 后缀键碰撞 1 例(curl `SetHTTPrequest.part.0` vs `SetHTTPrequest`)。

## 2. canonical vs direct-runner:桥接层缺口的解剖(任务②)

匹配:direct→canonical(地址按 0x100000 重归一 + 剥后缀名兜底);curl 74/74、
httpd 790/790。

| 语料 | 有差函数 | 总 diff 行 | push/extraout 族行(占比) | 去 push 族后残差 |
|---|---|---|---|---|
| curl | 69/74 | 3979 | 462(11.6%) | 3525(88.4%) |
| httpd | 787/790 | 38060 | 4973(13.1%) | 33199(86.9%) |

- push 族定义:diff 行含 `\w*Stack_[0-9a-fA-F]+`(xStack_/axStack_/iStack_…栈槽临时)
  或 `extraout_\w*`。存在性口径:7/74(curl)、85/790(httpd)函数呈现"direct 保留
  Stack_ 临时而 canonical 无";extraout_ 呈现 2/74、59/790,且 canonical 侧也有 3 个
  httpd 函数保留 extraout(headless 未全吸收,非单向)。
- **0/69、0/787 函数的桥接差是纯 push 族** —— 即不存在"只差 push"的函数,
  push 吸收判决永远伴随更大的环境差一起出现。
- 非 push 主体(抽样核验 my_get_line/pcre_compile/ap_core_input_filter 等):
  1. **原型轴**:canonical 带分析器原型(`char * my_get_line(FILE *fp)`),
     direct 全参数恢复(`uint4 * my_get_line(xunknown8 ×14)`);
     direct 侧含 xunknown 的函数 = curl 20/74、httpd 424/790。
  2. **类型轴**:direct `xunknown1/4/8` vs canonical `char*/uint/bool/undefined*`
     (含栈槽声明:`xunknown8 xStack_270;` vs `undefined8 uStack_270;`)。
  3. **控制流轴**:bad-instruction/jumptable 处理不同
     (canonical `free` → `halt_baddata()` vs direct `(*pcRam…)();`)。
  4. **符号轴**:direct 0 个 `DAT_` 行 vs canonical curl 16 / httpd 1295
     (BFD 符号直名 vs 分析器未命名全局)。
- 结论:**DP 判决"push 吸收是 analyzeHeadless 桥接层行为、库级保留"在方向与存在性上
  成立**(direct 侧 xStack token 490/5310 vs canonical 0/0,grep 实测;
  实例 `xStack_50 = 0x2cffb;` 于 direct 第 3810 行),但 push 族只是桥接层缺口的
  **少数(≈12-13% 行级)**;桥接层主体 = DP 移交项⑤"headless 桥接输入建模
  lane(参数锁/栈帧传递)"所指的无分析器环境差。
- 计数口径备注:DP 报告"httpd extraout/xStack 系 4557 处"与本 lane token 计数
  (1008 Stack-tmp + 330 extraout,790 匹配函数)不同源于计数约定(行/token/语料
  裁剪),方向一致。

## 3. Rugra(bf3f5064)对双基线读数(任务③)

### 3.1 E2E 运行记录

- curl:124/124 处理,76 decompiled,0 timeout,0 panic,48 external-stub(声明导入
  签名),rc=0。
- httpd 默认语料(MAX_FUNCS=30):29 函数,rc=0。
- httpd 扩展语料(MAX_FUNCS=840):**rc=139(SEGFAULT)**,死于第 227 个函数
  `ap_core_input_filter` 处理中(前 225 个函数头已完整刷出,224 个参与匹配)。
  → 开放项 HTTPD840-SEGV(§6.1)。

### 3.2 门禁口径读数(compare_ghidra.py,release+RUGRA_MIRROR)

| 语料×基线 | matched | skeleton | defects | numbering |
|---|---|---|---|---|
| curl 124 × canonical(--base 0x100000) | 124 | **4091** | 0 | 0 |
| curl × direct-runner(--base 0) | 117 | **3171** | 0 | 0 |
| httpd 29 × canonical | 29 | **4263** | 0 | 0 |
| httpd 29 × direct-runner | 29 | **4646** | 0 | 0 |
| httpd840 部分(224)× canonical | 224 | **18367** | 0 | **4**(全在 main) |
| httpd840 部分 × direct-runner | 224 | **19756** | 0 | **4** |

- curl 对 direct(3171)< 对 canonical(4091);httpd 相反(4646>4263、19756>18367)。
- 与 root 在 6b4ca15a 的亲测(curl 2585/0/0、httpd 2333/0/0)相比,bf3f5064 读数
  显著升高 → 开放项 MASTER-SKELETON-DRIFT(§6.2),非本 lane 裁决范围。

### 3.3 三方共识分解(核心证据)

方法:每函数把三方骨架行做成 multiset,按 `agree_all / R_eq_D_not_C /
R_eq_C_not_D / C_eq_D_not_R / R_only / C_only / D_only` 七桶分解
(R=Rugra,C=canonical,D=direct-runner)。multiset 忽略顺序,桶和与实测 Rc 的
覆盖率 ~84%(curl),其余为对齐噪声;方向性结论不受影响。

| 桶 | 含义 | curl N=117 | httpd29 N=29 | httpd840 N=224 |
|---|---|---|---|---|
| agree_all | 三方一致 | 832 | 507 | 2308 |
| R_eq_D_not_C | 桥接形态,Rugra 与库级 oracle 一致(canonical 门禁会记) | **975** | 390 | 1326 |
| R_eq_C_not_D | headless 建模形态,Rugra 与 canonical 一致(库级门禁会记) | **312** | 46 | 158 |
| C_eq_D_not_R | **两 oracle 一致而 Rugra 不同(真缺陷方向)** | **45** | **476** | **2106** |
| R_only | Rugra 自创行(无 oracle 打印) | **1084** | **2275** | **9866** |
| C_only | canonical 独有(analyzer 形态,库级不可达) | 1347 | 742 | 3851 |
| D_only | direct 独有(原始 BFD 契约形态) | 1266 | 1099 | 5444 |

- **canonical 残差的构成(curl)**:桥接形态 975(~28%)+ Rugra 自创 1084(~31%)
  + analyzer 形态 1347(~39%)+ 真缺陷方向 45(~1%)。即 canonical 门禁读数中,
  约 2/3 与契约歧义/分析器输入相关,约 1/3 是 Rugra 自身管线工作。
- **库级残差的构成(curl)**:headless 建模形态 312(~12%)+ Rugra 自创 1084(~40%)
  + direct 独有 1266(~47%)+ 真缺陷方向 45(~1.7%)。库级门禁会把 Rugra 已建成的
  桥接输入建模(312 行)判为缺陷。
- **push 赦免量化(DP 判决的账面价值)**:Rc 去 push 族后 curl 4087→3582(−12.4%)、
  httpd29 4263→4205(−1.4%)、httpd840 18367→17858(−2.8%)。
- **函数级**:curl 有 43 个 Rc=0 且 Rd>0 的"canonical 精确"函数——**全部 43 个都是
  `halt_baddata` PLT/thunk 族**(6-8 骨架行,例 `free`/`strcpy`/`curl_easy_perform`),
  即驱动侧 PLT 标记+bad-instruction 桥接数据的产物;纯桥接函数(Rd=0∧Rc>0)仅 1 个
  (main_free);双向都精确 2 个。httpd(29 与 224 两口径)canon-exact 与 pure-bridge
  均为 0 —— 深度函数在双基线上都未达到。
- **push 族形态 parity(curl,N=117)**:push 存储语句数 Rugra 252(8 函数)vs
  direct 218(7 函数)vs canonical 6;5/8 函数计数差 ≤1。DP"库级同形"在族级成立
  (Rugra 保留 +34 行的小幅超出),但 token 级拼写不同
  (`undefined8 uStack_270;` vs `xunknown8 xStack_270;`)——Rugra 的类型拼写跟随
  canonical 环境而非库级 raw 形态。

## 4. 裁决建议(任务④):**双基线分层门禁(选项三)**

### 4.1 为什么不是"库级为准绳改门禁"(选项一)

1. **语料覆盖硬上限**:direct-runner 只有 curl 74/124(59.7%)、httpd 790/2010
   (39.3%)。分析器发现的符号无名函数在 BFD 契约里**定义上不存在**,单一库级门禁
   对多数语料永久失明。
2. **激励倒挂**:库级门禁把 R_eq_C_not_D(312 行 curl / 43 个 canon-exact 函数)
   记为缺陷 —— 惩罚的恰是 master 已投资的桥接输入建模
   (MIRROR-ENVS-CANONICAL-0001、PLT 标记、DWARF 原型注入)。
3. httpd 实测对 direct 的残差(4646/19756)**高于**对 canonical(4263/18367):
   库级门禁不会更松,只会换一批差异。

### 4.2 为什么不是"canonical 为准绳 + 桥接建模车道"单轨(选项二)

1. C_only(analyzer 形态行)= curl 1347 / httpd840 3851,在纯 canonical 账本里永久
   留在缺陷侧,每族都要一次 DP 式人工判决(重讼成本)。
2. canonical 单轨没有契约独立的交叉验证:C_eq_D_not_R(45/2106)这类两 oracle 一致
   的差异才是无争议缺陷,单轨读不出这个优先级。

### 4.3 推荐方案:双基线分层门禁

- **L0 完整性前置**:门禁先验 golden sha256 + 输入指纹 + oracle commit
  (provenance 字段),任一不符禁止出数。
- **L1 硬零层(双基线都跑)**:defects=0、numbering=0 维持为合并硬门禁
  (当前:curl ✓✓、httpd29 ✓✓、httpd840 main numbering=4 ✗ → §6.3)。
- **L2 canonical 骨架预算(release 头条,全语料)**:维持现有预算口径与历史可比性;
  增设 **push 族赦免桶**(本报告正则,12.4%/2.8% 的量级),以 Rc_mod_push 为趋势
  指标 —— DP 判决的机器化,不再逐案人工讼。
- **L3 库级契约交叉核对(74/790 子集)**:每 commit 跟踪 Rd 与
  **C_eq_D_not_R(契约无关真缺陷,要求单调不增)**;R_eq_C_not_D(建模收益)与
  R_eq_D_not_C(桥接形态存量)作为结构监控,不计缺陷。
- **复审触发**:headless 桥接输入建模 lane(DP 移交⑤)落地后重跑本 census,
  预期 C_only 收缩、R_eq_C_not_D 增长;若 httpd840-SEGV 修复则扩展 httpd 统计面。
- 工具落地建议(不在本 lane 写域):consensus.py 并入 tools/ 作 `--threeway` 模式。

## 5. oracle 环境登记(如实)

- `/tmp/rugra-ghidra-bfd-2.38`:**在**(usr/include + usr/lib,
  libbfd-2.38-system.so 齐全)→ direct-runner 可重建。
- `/tmp/rugra-ghidra-1204-headless`(canonical 生成 dist):**已失**(机器重启;
  `tools/build_ghidra_1204_headless.sh` ~40min 可重建,ORACLE-0002 记录)。
- 本 lane 未重跑 oracle 生成器:四 golden 均有 sha256+provenance+第三方活性复现
  (MAINDIFF-DEADSTORE-0001)三重验证,重生成无增量信息。

## 6. 开放项(移交 root)

1. **HTTPD840-SEGV**(新):master bf3f5064,MAX_FUNCS=840 跑到第 227 函数
   `ap_core_input_filter` 时 SEGFAULT(rc=139,core dumped;29/226 语料不触发)。
   崩溃 lane 候选;修复后 httpd 三方统计面可扩到 ~790。
2. **MASTER-SKELETON-DRIFT-6B4CA15A→BF3F5064**(新):curl 2585→4091、
   httpd29 2333→4263(root 亲测 6b4ca15a vs 本 lane bf3f5064,同口径
   release+RUGRA_MIRROR)。区间 11 个 commit,候选:56f88fb2(MEMORY-class 参数
   bootstrap)、0a097498(ScopeLocal 参数符号)、79b75978/bf3f5064(cast 通道)。
   bisect lane 候选。
3. **numbering 语料序依赖**(新):httpd `main` 在 29 语料 numbering=0、在 840 语料
   numbering=4(同函数同二进制)→ 跨函数状态(callspec 发现序?)影响命名;
   varmap/printc 域,与 VARMAP-DUPDECL-EXTRAOUT-0001 可能同族。
4. **GOLDEN-CONTRACT-PUSHABSORB-0001 裁决本体**:本报告为量化输入,三选一决策
   归 root(建议已给:§4.3)。

## 7. 复现命令

```bash
# 桥接缺口(②)
python3 /dev/shm/rugra-tests/sb-goldenct/bridge_gap2.py
# 三方 + 共识(③) — 需要 rugra_curl.c / rugra_httpd*.c
python3 /dev/shm/rugra-tests/sb-goldenct/threeway.py rugra_curl.c rugra_httpd.c
python3 /dev/shm/rugra-tests/sb-goldenct/consensus.py rugra_curl.c rugra_httpd840.c
# Rugra E2E
RUGRA_MIRROR=1 /dev/shm/rugra-targets/sb-goldenct/release/examples/curl_decompile \
  > rugra_curl.c 2> rugra_curl.stderr.log
RUGRA_MIRROR=1 MAX_FUNCS=840 .../httpd_decompile > rugra_httpd840.c 2> ... # 见 §6.1 SEGV
# 门禁同源读数
python tools/compare_ghidra.py rugra_curl.c tests/golden/ghidra_curl_1204.c --summary-only
python tools/compare_ghidra.py rugra_curl.c tests/golden/ghidra_curl_1204.direct-runner.c \
  --base 0 --summary-only
```
