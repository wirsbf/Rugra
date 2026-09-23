# GOLDEN-CONTRACT-PUSHABSORB-0001 量化裁决报告(canonical vs direct-runner 双基线)

- 日期: 2026-09-23(Lane EG2 wt/goldenct 续跑收尾;基 master bf3f5064eaf89089732d40b7f45cf11679a51ea2,worktree clean)
- Oracle: Ghidra 12.0.4,commit `e40ed13014025f82488b1f8f7bca566894ac376b`(tag Ghidra_12.0.4_build;
  两侧 golden 的 `provenance.json` `oracle` 字段逐字核对同源)
- 语料: examples/curl(sha256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`)、
  examples/httpd(sha256 `805f89cdbdce827f8f6ccd877aa7c344ff1105713b7bf7b0e6f313affa93b1c1`)
  — 2026-09-23 本 lane sha256sum 重验,与两侧 golden provenance `input.sha256` 逐字节一致。
- Rugra 读数侧: bf3f5064 release 构建(CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-goldenct,
  `cargo build --release --example curl_decompile --example httpd_decompile`),驱动零环境变量
  (bare 模式,即历史门禁形态;curl stderr `[PREPASS] Imported 22 DWARF function prototypes`
  为 example 内建预扫,非 env 注入)。
- 度量: `tools/compare_ghidra.py` 的 `normalize_skeleton` 骨架 diff(本报告脚本直接 import 该模块,
  度量与差分门禁同源;行级 unified diff 的 +/- 行计数,n=0 上下文)。

## 0. TL;DR

1. **curl direct-runner golden 已存在且完整性验证通过**(2026-08-15 commit 0c912e90 入库,
   sha256 `56d0d317…` 与 provenance 一致;oracle/arch/cspec/输入指纹与 canonical 同源)。
   本 lane 未重跑 oracle(见 §7),做完整性+血缘+活性三重复核。
2. **DP 的 push 吸收判决成立**(方向+存在性):direct-runner(库级)保留 `Stack_`/`extraout_`
   打印,canonical(analyzeHeadless)吸收——桥接差中 direct 侧 push token 490/5310 个 vs
   canonical 9/135 个(curl/httpd)。但 push 族只占桥接层缺口的 **11.6%(curl)/13.1%(httpd)**
   行级 diff;桥接层主体是"无 Java 分析器"环境差(原型/类型/jumptable/引用,~87-88%)。
3. **Rugra(bf3f5064)三方读数推翻了"库级基线更容易达标"的隐含预期**:Rugra 对 canonical 的
   残差 **小于** 对 direct-runner 的残差(curl 2557 vs 4313,httpd 25327 vs 36984)。canonical
   残差在库级基线下不是"消失"而是**恶化 +69%/+46%**;纯桥接函数(库级基线下归零)仅
   1/117(curl)、0/467(httpd)。Rugra 的 E2E driver 是 headless 形态(DWARF 原型+全局符号层
   等已建模),44/117 curl 函数 canonical-精确但库级基线下反被判差。
4. 裁决建议:**双基线分层门禁**(§5)——canonical 继续作回归门禁(准绳不变),
   direct-runner 降位为"库级真值仪表盘"(跟踪 `C=D≠R` 双 oracle 一致而 Rugra 偏差的行 =
   真库级缺陷方向:httpd 4661 行 / curl 63 行),不做 pass/fail。

## 1. 基线资产与完整性(任务①)

| 文件 | 函数数 | 行数 | sha256(2026-09-23 重验) | 入库 commit |
|---|---|---|---|---|
| tests/golden/ghidra_curl_1204.c(canonical) | 124 | 3318 | `aca37988…` | 0c912e90 |
| tests/golden/ghidra_curl_1204.direct-runner.c | 74 | 3061 | `56d0d317…` | 0c912e90 |
| tests/golden/ghidra_httpd_1204.c(canonical) | 2010 | 66637 | `6b4c4f31…` | 0c912e90 |
| tests/golden/ghidra_httpd_1204.direct-runner.c | 790 | 37456 | `ead6e3bf…` | 0c912e90 |

- 生成管线(读 provenance+tools 复核):canonical = `tools/build_ghidra_1204_headless.sh`
  构建的锁定源码 headless dist → `tools/regen_ghidra_golden.py` 驱动 analyzeHeadless 默认
  分析 + decompile-all postScript(30s/函数);direct-runner = 同一锁定 cpp 树
  `make decomp_opt`(BFDHOME=/tmp/rugra-ghidra-bfd-2.38/usr)+ 内嵌 golden_dump_1204.cc
  driver(fixture sha c82028e4…),BFD 符号表发现函数、每函数独立进程(hermetic),
  600s/函数,16 并发;provenance 记录 12 样本 byte-identical。
- 独立复现证据:MAINDIFF-DEADSTORE-0001(2026-08-25)用 /tmp/ds_oracle 自建 instrumented
  同版本 driver 直跑,输出与入库 direct-runner golden **字节一致**(104/104 `Stack_260=`
  全保留)→ 入库文件活性再验证。
- 输入指纹:两侧 golden provenance `input.sha256` 与当前 examples/{curl,httpd} 逐字节一致
  → 无输入漂移,双基线可直接对拍。
- 本 lane 判定:curl direct-runner golden **无需重生成**;登记差异:direct-runner 函数发现
  =BFD 符号表(curl 74 vs canonical 124;httpd 790 vs 2010),canonical 的分析器发现函数
  在 direct 侧结构性缺席(provenance equivalence_risks 已列)。

## 2. canonical vs direct-runner 逐函数骨架差(任务②,oracle-internal 桥接层缺口)

匹配:direct→canonical,地址按 0x100000 重归一+剥 GCC 后缀名兜底。curl 74/74 匹配
(1 个键碰撞:SetHTTPrequest.part.0 与 SetHTTPrequest 剥后缀同名,canonical 只有主函数);
httpd 790/790 匹配。**本 lane 重跑 bridge_gap2.py 数字不变**(2026-09-23 复核)。

| 语料 | 匹配 | 有差函数 | 总 diff 行 | push/extraout 族行(占比) | 去 push 族后残差行 |
|---|---|---|---|---|---|
| curl | 74 | 69 | 3979 | 462(11.6%) | 3525(88.4%) |
| httpd | 790 | 787 | 38060 | 4973(13.1%) | 33199(86.9%) |

- push 族定义:diff 行含 `\w*Stack_[0-9a-fA-F]+` + `extraout_\w*`。token 计数:direct 侧
  490(curl)/5310(httpd)vs canonical 侧 9/135 → **库级保留、headless 吸收,方向单向成立**。
- 非 push 主体(抽样核验,my_get_line/pcre_compile 等):①原型轴——canonical 带分析器原型
  (`FILE *fp`),direct 全 `xunknown8` 参数恢复(curl 20/74、httpd 424/790 函数 direct 侧含
  xunknown);②类型轴(xunknown1/4/8 vs char*/uint/bool);③控制流轴(bad-instruction/
  jumptable 恢复差异);④符号轴(direct 0 个 DAT_,canonical curl 16/httpd 1295 行)。
- **结论**:DP 判决"push 吸收是 analyzeHeadless 桥接层行为、库级保留"成立;但 push 族只是
  桥接层缺口的一个小家族(≈12-13% 行级),主体是"无 Java 分析器"环境差,与 DP 移交项⑤
  "headless 桥接输入建模 lane"同一所指。

## 3. Rugra(bf3f5064)对双基线读数(任务③)

### 3.1 门禁口径(compare_ghidra.py,skeleton/defects/numbering)

| 语料 | Rugra 输出 | vs canonical(--base 0x100000) | vs direct-runner(--base 0) |
|---|---|---|---|
| curl(124 fns:76 反编译+48 import-stub) | rugra_curl_v2.c | **2561/0/0** | 4313/0/0(117 匹配) |
| httpd 门禁面(29 fns,MAX_FUNCS 默认 30) | rugra_httpd_gate.c | **2333/0/0** | 2906/0/0 |
| httpd 全量(467 fns,MAX_FUNCS=840) | rugra_httpd_full.c | (3.2 三方口径) | 36984/**2**/0 |

- canonical 侧 2561/2333 与亲父 bf3f5064 基线亲测恒等(0/0)——**本 lane 复核通过**。
- httpd 全量对 direct 侧出现 2 个 defects:`ap_parse_uri`(空 else,line 16)、
  `ap_invoke_handler`(空 else,line 57)——均在 29 函数门禁面之外的全量暴露面,非本 lane
  引入(本 lane 零 src 改动);建议 root 登记 TODO(见 §6)。

### 3.2 三方逐函数口径(三侧共有的 N 个函数,骨架 diff 行)

| 语料 | N(三侧共有) | ΣRc(对 canonical) | ΣRd(对 direct) | ΣB(桥接差) | Rd−Rc | Rc 中 push 行 | Rd 中 push 行 |
|---|---|---|---|---|---|---|---|
| curl | 117 | 2557 | 4313 | 4386 | **+1756** | 224(8.8%) | 618(14.3%) |
| httpd | 467 | 25327 | 36984 | 35367 | **+11657** | 695(2.7%) | 5023(13.6%) |

函数级分布:

| 语料 | Rd=0∧Rc>0(纯桥接) | Rc=0∧Rd>0(canonical-精确但库级判差) | 双零 | 双正 |
|---|---|---|---|---|
| curl | **1**/117 | **44**/117 | 2 | 70 |
| httpd | **0**/467 | **6**/467 | 0 | 461 |

**核心事实:Rugra 对 canonical 比对 direct-runner 更近**(每函数 Rd≥Rc 占绝对主导)。
库级基线下残差不缩小反放大:+69%(curl)/+46%(httpd)。

### 3.3 共识分解(行多重集,R= Rugra,C= canonical,D= direct;N 同上)

| 语料 | agree_all | R=C≠D(headless 已建模) | R=D≠C(桥接形态) | **C=D≠R(真库级缺陷方向)** | R_only | C_only | D_only |
|---|---|---|---|---|---|---|---|
| curl | 814 | 759 | 217 | **63** | 899 | 900 | 2024 |
| httpd | 4333 | 340 | 855 | **4661** | 8160 | 9697 | 21469 |

- `R=C≠D`:Rugra 与 canonical 一致、direct 因无分析器而不同的行(headless 建模成果的直接读数)。
- `C=D≠R`:**两个 oracle 独立一致而 Rugra 偏差**——任何基线下都成立的真库级缺陷方向。
- push 盲化后(mod-push):curl Rc 2557→2333、Rd 4313→3693;httpd Rc 25327→24506、
  Rd 36984→31893——push 族在 Rugra 的库级侧残差占比 14.3%/13.6%,与桥接层族占比同量级。

### 3.4 每函数 top 差异

curl,按 Rc(对 canonical)top:

| 函数 | Rc | Rd | B |
|---|---|---|---|
| getparameter | 743 | 859 | 792 |
| main | 581 | 925 | 860 |
| file2string | 123 | 130 | 143 |
| next_url | 103 | 138 | 145 |
| parseconfig | 99 | 148 | 167 |

curl,库级基线下恶化最多(Rd−Rc):

| 函数 | Rc | Rd | Δ |
|---|---|---|---|
| main | 581 | 925 | +344 |
| glob_word | 21 | 317 | +296 |
| my_get_line | 61 | 238 | +177 |
| helpf | 77 | 199 | +122 |

httpd,按 Rc top:

| 函数 | Rc | Rd | B |
|---|---|---|---|
| pcre_compile | 1017 | 1059 | 1576 |
| ap_directory_walk | 844 | 936 | 942 |
| ap_core_output_filter | 837 | 761 | 732 |
| ap_http_filter | 761 | 813 | 852 |
| ap_mpm_run | 677 | 746 | 711 |

httpd,库级基线下恶化最多(Rd−Rc):

| 函数 | Rc | Rd | Δ |
|---|---|---|---|
| ap_soak_end_container | 72 | 800 | +728 |
| ap_process_resource_config | 102 | 735 | +633 |
| ap_core_input_filter | 405 | 939 | +534 |
| ap_process_config_tree | 59 | 564 | +505 |
| ap_basic_http_header | 18 | 504 | +486 |

恶化 top 函数(my_get_line、glob_word、ap_process_resource_config 等)正是桥接层原型/
类型轴的重灾户:canonical 有分析器数据而 direct 全 xunknown,Rugra 跟随 canonical。

## 4. Rugra 残差分解(任务④:桥接层结构性不可达 vs 库级真实残差)

原问题:"对 canonical 的残差中,多少在 direct-runner 基线下消失(=桥接层结构性不可达)
vs 仍在(=库级真实残差)"。量化答案(§3.2/§3.3):

1. **消失份额 ≈ 0**:纯桥接函数 curl 1/117、httpd 0/467;行级 ΣRd>ΣRc(双 corpus 皆反号)。
   **没有可观的残差家族"在库级基线下消失"**——前提本身不成立:Rugra 的 driver 不是
   "库形态",而是 headless 形态(DWARF 原型预扫、MAINDIFF-GLOBAL-0001 全局符号层、
   libc 签名等桥接建模已落地并在门禁口径内)。
2. **库级基线是一次视角切换而非难度减免**:它把 44/117(curl)个 canonical-精确函数重新
   判差(R=C≠D 759 行 + C_only 900 行的代价),同时暴露 canonical 门禁看不到的盲区——
   `C=D≠R`(双 oracle 一致而 Rugra 偏差)= 真库级缺陷方向,curl 63 行 / httpd 4661 行,
   httpd top 集中在 pcre_compile/ap_directory_walk/ap_core_output_filter/ap_http_filter。
3. **DP push 判决验证(任务②库级侧)**:direct-runner golden 保留 push 打印(token 490/5310
   vs canonical 9/135);Rugra 的库级侧残差中 push 行占 14.3%/13.6%,与 oracle-internal
   桥接差中 push 族占比(11.6%/13.1%)同量级——push 吸收确为桥接层行为、库级保留,
   且是桥接层缺口的少数族。

## 5. 裁决建议(任务⑤):双基线分层门禁

**建议:方案三——双基线分层门禁。**

| 层 | 基线 | 角色 | 判定 |
|---|---|---|---|
| L1 回归门禁 | canonical 12.0.4(不变) | pass/fail:防止已落地的 headless 建模回退;与现行机制 B 同源 | defects=0∧numbering=0,skeleton 单调收敛 |
| L2 库级真值仪表盘 | direct-runner 12.0.4 | 只读 KPI:`C=D≠R` 行数、ΣRd、全量 defects(如 httpd 2 处空 else) | 不做 pass/fail;作为库级缺陷 backlog 排序依据 |

理由:

1. **否决方案一(库级为准绳改门禁)**:Rugra 当前形态下数字全面恶化(curl +69%、
   httpd +46%),44/117 curl canonical-精确函数被误判,等于惩罚 MAINDIFF-GLOBAL-0001/
   DWARF 原型/symfield 等已验证落地的建模成果;且 direct golden 函数发现面窄
   (74/790 vs 124/2010,BFD 符号表 only),门禁覆盖反而缩水。
2. **否决方案二(单独建桥接建模车道)**:桥接建模已经是现状(curl driver 已 headless 形态,
   R=C≠D 759 行即其读数),再建车道无增量;它也解决不了 canonical 门禁的盲区——
   canonical 残差把"分析器环境差"与"真库级缺陷"混在一起,只有 D 侧共识
   (`C=D≠R`)能把后者分离出来。
3. **方案三的增量**:L2 用零改造代价(脚本已在 lane 产物)把 63/4661 行真库级缺陷方向
   变成可跟踪 KPI,给 jumptable/类型轴修复排优先级;L1 保持门禁连续性(2561/2333 0/0
   基线不受影响)。DP 移交项⑤的"headless 桥接输入建模"按此并入 L2 观测而非新建车道。

## 6. 新观测信号(待 root 登记)

- httpd 全量(467 fns)对 direct 侧 2 defects:`ap_parse_uri` 空 else(line 16)、
  `ap_invoke_handler` 空 else(line 57)。29 函数门禁面外暴露,非本 lane 引入(零 src 改动),
  建议登记 TODO 并归入 L2 仪表盘初始 backlog。
- 桥接层原型轴重灾户(my_get_line/glob_word/ap_process_resource_config 等,Rd−Rc>+500)
  与 DP 移交项⑤同所指,若未来做 L2 收敛,优先级应给 `C=D≠R` 而非桥接差本身。

## 7. 环境与血缘登记

- /tmp/rugra-ghidra-bfd-2.38:在(usr/include usr/lib,libbfd-2.38-system.so 齐全)。
- /tmp/rugra-ghidra-1204-headless(canonical 生成 dist):已失(重启丢失;可由
  tools/build_ghidra_1204_headless.sh ~40min 重建,ORACLE-0002 记录)。
- 本 lane 未重跑 oracle 生成器:两侧 golden 均有 sha256+provenance+第三方独立复现
  (MAINDIFF-DEADSTORE-0001)三重验证,重生成无增量信息;direct-runner 活性复跑配方
  已在 TODO MAINDIFF-DEADSTORE-0001 行登记。
- **前任会话陈旧产物事故(已排除)**:前任 13:02 生成的 rugra_curl.c 读数 4091/0/0,
  与 bf3f5064 基线 2561 不符;根因=陈旧二进制(line 17 `pRam0000000000016fe8` vs 正确
  `PTR___gmon_start___00116fe8`,MAINDIFF-GLOBAL-0001 符号层缺失形态)。本 lane 以当前
  worktree 干净树重建 release 并复跑全部 E2E(2561/2333 0/0 双双复现),陈旧产物
  (rugra_curl.c/rugra_httpd.c/rugra_httpd840.c)已从 lane 产物目录清除。教训:接手
  中断会话的 E2E 产物必须先做基线复核再消费。

## 8. 复现命令

```bash
# 构建 + E2E(本 lane 实测形态,bare 模式)
CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-goldenct cargo build --release \
  --example curl_decompile --example httpd_decompile
/dev/shm/rugra-targets/sb-goldenct/release/examples/curl_decompile          # > rugra_curl_v2.c
/dev/shm/rugra-targets/sb-goldenct/release/examples/httpd_decompile         # > rugra_httpd_gate.c(29 fns)
MAX_FUNCS=840 /dev/shm/rugra-targets/sb-goldenct/release/examples/httpd_decompile  # > rugra_httpd_full.c(467 fns)

# 门禁口径
python3 tools/compare_ghidra.py rugra_curl_v2.c   tests/golden/ghidra_curl_1204.c             --summary-only          # 2561/0/0
python3 tools/compare_ghidra.py rugra_httpd_gate.c tests/golden/ghidra_httpd_1204.c            --summary-only          # 2333/0/0
python3 tools/compare_ghidra.py rugra_curl_v2.c   tests/golden/ghidra_curl_1204.direct-runner.c   --base 0 --summary-only  # 4313/0/0
python3 tools/compare_ghidra.py rugra_httpd_full.c tests/golden/ghidra_httpd_1204.direct-runner.c --base 0 --summary-only  # 36984/2/0

# 三方量化 + 共识分解 + 桥接缺口(lane 脚本,/dev/shm/rugra-tests/sb-goldenct/)
python3 threeway.py  rugra_curl_v2.c rugra_httpd_full.c   # threeway.json
python3 consensus.py rugra_curl_v2.c rugra_httpd_full.c   # consensus.json
python3 bridge_gap2.py                                    # oracle-internal,不依赖 Rugra 输出
```
