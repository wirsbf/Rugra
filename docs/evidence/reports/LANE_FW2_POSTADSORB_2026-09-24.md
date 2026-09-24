# Lane FW2 终报 — 并集验证 + POSTADSORB-CONVERGE 处置 (wt/postadsorb)

- worktree: /dev/shm/rugra-worktrees/postadsorb, branch wt/postadsorb
- 基础: 并集 **781046c2** (= FM rulearith 26ffb3c2 × master 9458a61b,本 lane 为并集所有者)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b
- 日期: 2026-09-24; commit **5b21e038**(R1/R2 处置 + TODO/docs 同 commit);
  CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-postadsorb
- 证据: /dev/shm/rugra-tests/sb-postadsorb/(E2E 双语素前后对照、五投影+bisect、
  InferTypes 插桩计数、final_gates.txt、commit_msg.txt、run_e2e.sh/run_proj.sh)

## A. 并集门禁全套(root 委托;CR24 已 APPROVE FM 本体)

| 门禁 | 并集 781046c2 | master 9458a61b | FM 声明(基 06034903) | 判定 |
|---|---|---|---|---|
| curl E2E | **2145/0/0** | 2145/0/0 | 2155/0/0(+3=警告行) | 并集==master 基线,零警告 ✓ |
| httpd E2E | **2057/0/0** | ~2057 | 2225/0/0 | master 侧车道(CALL-PUSH/CONCATRAM 等)收敛,并集无回退 ✓ |
| parseconfig 投影 | **MATCH** | (FM 前 ord186 分歧) | MATCH | **FM 收获保持** ✓ |
| next_url 投影 | **MATCH** | — | MATCH | 保持 ✓ |
| match_url 投影 | **MATCH** | — | MATCH | 保持 ✓ |
| gp 投影首分歧 | **ord351**(mergerequired) | — | ord209(oppool1 29v32) | **209→351 后移 142**,stages 587→**371==oracle** ✓ |
| myprogress 投影首分歧 | **ord399**(setcasts 5v6) | — | ord173(oppool1 7v10) | **173→399 后移 226**,stages **402==oracle** ✓ |
| --func getparameter | **532** | — | 533 | ≤533 ✓(−1=警告行消失) |
| --func myprogress | **64** | — | 65 | ≤65 ✓ |
| gcc 审计 | **82 OK / 25 FAIL** | 82/25 | 82/25 | ==父 ✓ |
| 单测 --lib | 1684-1685 passed/17-20 failed | 已知集 | 已知集 | 失败=funcdata alignment/ssa flaky 族+heritage_creation@master,单跑过/连续两轮 17↔20 摆动=顺序敏感 flake;**零新增** ✓ |
| 吸附形态在位 | match_url `&0x...feb8+(uVar-8)` base+field 分解 | 单体 `feb0+uVar+6` | 同并集 | FM 语义并集存活(E2E 与 master 逐字节对比确认差异行即吸附形态) ✓ |

并集语义缺口排查(CR24 提示⑤):**未发现**。`LiveSpacebaseMap`(FN 侧,get_map 投影)与
`SpacebaseMap`(FM 侧,ruleaction 查询线程化)两枚举职责正交、无孤儿代码;帧判别
`!localframe.is_invalid() || !localframe.is_null()`(ruleaction.rs)/`!is_null()`
(datatype.rs get_map) 的全零 sentinel 形态**在本仓模型下是唯一可观测等价**——验证:
legacy `Address::new(vaddr)` 无 space(全部 Funcdata 构造点)→`is_invalid()` 对真实
函数入口恒真,裸 `!is_invalid()` 会废掉 Local 腿;`get_type_spacebase` 全部调用方传
spaceless frame 或 `Address::new(0)`。CR24 条件("若 FN 通道带来带 space 的 Address")
**不成立**,sentinel 形态保留并在注释中记录;未来 ADDRESS 阶段二带 space 帧落地时切换
真值判别。

## B. POSTADSORB-CONVERGE 处置(三条 InferTypes 不收敛警告)

**结论:并集态三条警告全部消失,且是真实收敛而非压抑制。**

1. **E2E plain-run**:curl 124 函数 + httpd 29 函数 `not settling` 警告 **0 条**
   (FM 基 06034903 时为 3 条:file2string.part.0/getparameter.constprop.0/match_url)。
2. **插桩实证**(临时 env 探针 `RUGRA_DBG_INFERPASS`,已还原,commit 内容无探针):
   三函数 writeBack 变更轮数 max localcount = **3/5/5**(< 7 阈值),InferTypes 在
   数据流传播中真实收敛;myprogress=3/parseconfig=3/next_url=4 同收敛。
3. **loop 收敛对拍**:gp 投影 stages 587(FM 基)→**371==oracle**;myprogress
   **402==oracle**。fullloop 迭代不再多于 oracle。
4. **语义核对**(铁律 1.2,coreaction.cc:5374-5416 全函数体已读):apply 的
   hasTypeRecoveryStarted 门/localcount≥7 警告+setTypeRecoveryExceeded/
   buildLocaltypes/迭代过滤(annotation、unwritten+no-descend)/propagateAcrossReturns/
   propagateSpacebaseRef/writeBack→localcount++ 逐项在位;`canonicalize_temp_type`
   interning 不变量(EO2 sb-typesettle 先例锚点)在位。唯 `applyTypeRecommendations`
   (cc:5398)未移植——oracle 双生产者(prepareThisPointer funcdata_varnode.cc:1742/
   collectNameRecs varmap.cc:374)均为 C++ this-指针域,本 C 语料 typeRecommend 恒空=
   no-op,不可观测(未登记为新 TODO,如 C++ 语料落地需补)。
5. **根因归因(curing 通道=master 06034903..9458a61b)**:主通道=4f4c9d78
   (VARMAP-STACKBOUNDARY live_local_scopes/publish_scope_to_spacebase)+
   4256a1a7(FN spacebase live scope cells)——live ScopeLocal 通道使吸附产
   PTRSUB+INT_ADD 修正式的类型每轮解析到与 oracle 相同的视图(旧态=构造期全局
   scope 快照 stale→跨轮类型往返翻转≥7);辅通道=13f080fd/f8ee7548(输入原型域,
   file2string 即 SB-F2STRING 函数)。FO lane(块覆盖锚定)与警告族无域交集。
   ①投影域同族残差(oppool1 +3)一并消失(见 A 表 ord 后移)。

## R1/R2 登记核验(CR24 排队提示处置)

- **R1(biggest_non_mult_coeff u32 化+三处截断时点镜像)— 已修**(commit 5b21e038)。
  核验发现 FM 注释声明"uint8 字段"有误:oracle 字段本就是 `uint4`
  (ruleaction.hh:54),形参 `uint4 coeff`(cc:6064),调用点零截断。Rust 字段
  u64→u32;三位点截断时点逐点镜像:cc:6146 **先转换后比较**(|sval|≥2^32 回绕值
  可为 0 落选)、cc:6158-6159/6210-6211 **64 位宽比较后截断存储**(treeCoeff=uint8,
  ruleaction.hh:70-72);`!=0`(cc:6271)与吸附消费读存储值。勘误入
  docs/api/ruleaction.md。
- **R2(SPACEBASE 臂无符号除)— 已修三处 off 位点 + fixture 缺口登记**。
  `AddrSpace::byteToAddress(uintb val,uint4 ws)=val/ws`(space.hh:522-524)是
  无符号除;`get_sub_type`/`get_sub_type_in_map`/`nearest_arrayed_component_
  forward_in_map` 三处由 i64 有符号除后转 u64 改为 `(off as u64).wrapping_div(ws
  as u64)` 按补码位型除(负栈偏移 -0x4e8 在 ws>1 时的 oracle 商形态)。ws=1 恒等,
  双语素逐字节不变;wordsize>1 双侧 fixture 缺口登记 **`RULEARITH-SPACEBASE-
  USDIV-0001`(P3 latent,新 TODO 行)**。
- 两处 `byte_to_address_int` 副本(datatype.rs:1978/ruleaction.rs:19215)现仅收
  正尺寸参数,符号性不可观测,保持现状(R2 行内注明)。

**corpus-neutral 证明**:R1/R2 前后 curl+httpd E2E 输出 **cmp 逐字节相同**;五投影
状态逐项相同(MATCH×3 + ord351/ord399 保持);datatype 域 69/69 测试绿。

## 剩余残差移交(区间分治确认)

1. **gp ord351** `universal:mergerequired` BUILD 第二输入:oracle `n:stack:...fa48`
   (命名栈变量) vs rugra `u:1000064d`(unmerged unique 临时)→ **merge/varmap 域**
   (TODO 行已注记,merge 域车道候选;非 InferTypes/非本 lane write-set)。
2. **myprogress ord399** `universal:setcasts` result/count 5 vs 6(+1)→ **FV2
   SetCasts 臂车道域内**(同文件区间分治约定:FV2=SetCasts,FW2=InferTypes 循环——
   循环侧已收敛交付)。

## CR25 复核请求(ruleaction.rs Rule 白名单 + datatype.rs spacebase 查询族)

请独立 reviewer 自行打开 Ghidra 行复核(勿采信本报告声明),重点:

1. **R1 三位点截断时点**:ruleaction.cc:6146-6147(先转换后竞争)vs cc:6158-6159/
   6210-6211(uint8 宽竞争后截断存储)的次序镜像;Rust `sval.wrapping_neg() as u32`
   对 sval<0 与 C++ `(uint4)-sval` 低 32 位等价性(含 i64::MIN 边界)。
2. **R2 无符号除**:space.hh:522-524 uintb 语义;三 Rust 位点 `(off as u64)
   .wrapping_div(ws as u64)` 在 ws=1 恒等、负 off+ws>1 补码位型商的对应;
   :4524(size 位点,恒正)保持有符号除是否等价。
3. **并集决策**(TODO 行 RULEARITH-POSTADSORB-CONVERGE-0001 注记):帧判别 sentinel
   形态保留的条件核验(全部 `get_type_spacebase` 调用方 spaceless;
   `Address::is_invalid()=space.is_none()`);两枚举 LiveSpacebaseMap/SpacebaseMap
   职责划分无重影。
4. **警告消失归因**:插桩计数 3/5/5<7 与 stages==oracle 的证据链
   (sb-postadsorb/inferpass_*.stderr、gp/myprogress_bisect.txt)。

## 回收

- worktree 保留(待 root 集成 + CR25);/dev/shm/rugra-targets/sb-postadsorb 保留
  (root 复验增量缓存),lane 收尾后按回收纪律处理。
- result/curl_cur.c 已回流(worktree 内,gitignored,=curl_e2e_r12.c)。
- 证据件:/dev/shm/rugra-tests/sb-postadsorb/{curl_e2e,httpd_e2e}(_r12).c+stderr、
  *_bisect.txt×5、inferpass_*.stderr×6、final_gates.txt、commit_msg.txt、
  fail_names_final.txt、run_e2e.sh/run_proj.sh。
