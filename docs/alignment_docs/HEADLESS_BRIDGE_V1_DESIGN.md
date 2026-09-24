# HEADLESS_BRIDGE_V1_DESIGN — headless 桥接建模 v1:加料通道归因与驱动侧设计

- Lane: BRIDGE1(wt/bridge1,自 master dc70528c)
- 日期: 2026-09-24
- 性质: 归因+设计车道(docs-only,零 src 改动)
- 语料: `tests/golden/ghidra_{curl,httpd}_1204.c`(headless 正典) vs `.direct-runner.c`(库级契约),双 golden 同源锁定 oracle(Ghidra 12.0.4 e40ed130,provenance 在库)
- 实验产物: `/dev/shm/rugra-tests/bridge1/`(parse_golden.py / diff_channels.py / diff_canon.py / diff_hunks.py + 4 份 JSON 结果)
- 结论先行: **未建模加料通道共 8 族,v1 主攻 C1 类型播种(committed local 层)** —— httpd 侧 5824 处 `local_` 引用 / 3173 行 typed 声明,是 direct-runner 完全没有的一整层,且已被 SPALIAS drill 证明单函数 oracle 无法从库内收敛得到。驱动侧等价实现 = golden 收割 manifest + worker 在 action 前向 `ScopeLocal` 播种 typed 符号(镜像 Ghidra `<localdb>` XML 协议,varmap.rs:1950 消费链已在位)。

---

## §0 为什么需要这个设计(三判例的战略前提)

FI 判决(sb-spillpair)已把口径钉死:**Rugra 库级输出 vs direct-runner golden 同形 = 正确终态;与 headless 正典 golden 的残差中,有一整族是"headless 环境输入"而非库缺陷**。DP 判决(sb-pushabsorb)同样明言:canonical 口径要达到"push 消失"必须先建模 headless 桥接输入(参数锁/栈帧/analyzer 传递),属新 lane。SPALIAS drill(VARMAP-SPALIAS-RETYPE-0001)则给出铁证:hermetic 单函数 oracle 与 Rugra 同收敛到 unknown 固定点 ⇒ golden 的 `long local_c8[4]` 种子在**库外**。GC 判例(sb-boollit):golden bool 声明 168 vs 库级 `'\x01'` = Java Data Type Propagation 层。

即:**headless golden = C++ 库 + Java 分析器栈的提交物回灌**。库忠实 ≠ 输出等同;要追平正典,必须把 Java 侧的"加料"在驱动侧等价重建 —— 照 EX2(LAB_)/GA(switchD)/GD2+GJ(coderef)/EP(FS canary) 已验证的"驱动侧加料,库保持纯净"模式。

## §1 两个 golden 的结构性差异(证据边界)

| 维度 | headless 正典 | direct-runner |
|---|---|---|
| 生成 | 单进程 analyzeHeadless:完整 Java 默认分析(loader/PLT/references/demangler/FID/DWARF,无选项覆盖)→ postScript 同 JVM 逐函数反编译(`tools/ghidra_decompile_all.py`,DecompInterface 默认选项) | `golden_dump_1204` fixture:BfdArchitecture + BFD/PLT 符号注册,逐函数 hermetic 进程,完整 universal action(FIXTURE_CPP,regen_ghidra_golden.py:153-402) |
| 函数集 | curl 124 / httpd 2010 | curl 74 / httpd 790(差集=analyzer 发现+plt.sec thunks) |
| 地址基 | 0x100000 | 0(PIE VMA) |
| provenance | `direct_runner_cross_check.equivalence_risks` 明列 6 条通道级差异(analyzer 栈/DWARF 原型/thunk 发现/名字剥离/导入符号/跨函数状态) | 同左 |

双 golden 即现成的差分对:**凡 headless 有而 direct-runner 无的形态,按定义是 headless-only 加料**(FI 判例口径);再用 curl(带 DWARF)vs httpd(stripped)对照区分 DWARF 源与 analyzer 源。

## §2 加料通道清单(量化 + 归因 + 现状)

量化口径:diff 为函数块级配对(74/790 对齐函数),hunk=SequenceMatcher 差异块(变量名归一后);grep 行数为全文件口径。`H`=headless 正典侧,`D`=direct-runner 侧。

| # | 通道 | curl 量化 | httpd 量化 | 归因(golden 知道什么/从哪知道) | 驱动桥现状 |
|---|---|---|---|---|---|
| C1 | **TYPE-SEED-LOCAL**(committed `local_*` 符号+类型层) | `local_` 引用 117,typed 声明 140 vs D undefined 326 | **`local_` 引用 5824(D=0),typed 声明 3173 vs D 4468**;TYPE-SEED hunk 316 | **Java 分析器提交环**:Decompiler Parameter ID(含 locals 提交)先跑库恢复→提交 DB→Data Type Propagation 等再升级类型→最终反编译读回。证据:①httpd stripped 无 DWARF 仍有 typed locals ⇒ 非 DWARF;②SPALIAS drill:hermetic oracle 收敛 unknown ⇒ 库外种子;③`local_` 名 C++ 全树零生成点(grep 无)⇒ 名字来自 Java DB;④C++ 消费机制在锁定源:`<localdb>`(funcdata.cc:804-810)→ `MapState::gatherSymbols`(varmap.cc:1044-1059)→ `RangeHint::fixed+typelock` | ❌ 未建模(SPALIAS/GC/FI/DP 四判例残差的上游总根) |
| C2 | **THUNK-GOT**(GOT 槽 `PTR_x` 符号化 + thunk 标记 + 导入函数签名) | PTR_ 50 vs pcRam 313;THUNK-PAIR hunk 73;locked-storage 警告 51(D=0);D jumptable 警告 46(H=0) | PTR_ 372 vs pcRam 1659;THUNK-PAIR hunk 495;locked 警告 124;D jumptable 警告 431 | headless ELF loader+分析器:建 GOT 引用符号(`PTR_<extname>_<addr>`、`code*` 型)、把 PLT/plt.sec 标记为 thunk(免 jumptable 恢复)、对导入函数套用库签名(锁定参数存储)。httpd stripped ⇒ 签名来自 FID/外部签名库,非 DWARF | 部分:GOT PTR_ 标签+函数符号已桥(driver :557-563);**导入签名/thunk 标记/警告抑制 ❌** |
| C3 | **SIG-LOCK 实函数**(原型锁定+参数名) | SIG hunk 22 + PARAM-NAME 26;`__x` 参数名 263 vs 72 | SIG hunk 418 + PARAM-NAME 146;`__x` 1562 vs 332 | curl=DWARF 函数原型(argc/argv/__stream/urls);httpd=analyzer 签名(FID/Parameter ID 提交)。与 C1 同机制不同载体(`<prototype>` 锁,fspec) | 部分:DWARF 自身+callsite 锁、24 libc 已桥(CALLSPEC-ENV-SCOPE-0001/GL);**导入面与 golden-harvest 面 ❌** |
| C4 | **STRUCT-FIELD**(DWARF 组合类型下的字段步进) | STRUCT-FIELD hunk 33 + GLOBAL-SYM hunk 119(`::config`/`outs.stream`/`stdin` 等 typed 全局) | STRUCT-FIELD hunk 26(归因开放:stripped 下疑 FID 套型) | curl=DWARF composite(Configurable/URLGlob/FILE);全局符号带类型 | 部分:TYPEDEF_PREAMBLE 文本级 hack(:4845);真组合类型 ❌ |
| C5 | STRSYM(字符串字面量实参) | H 43 vs D 0 | H 1681 vs D 10 | Java string/reference 分析器在 .rodata 建字符串数据 | ✅ 已桥(driver 字符串通道) |
| C6 | BOOL-LIT 残余(Data Type Propagation 族) | true/false 34 vs 18 | 499 vs 289 | GC 判例:Java Data Type Propagation 把 bool 语义播种到库级 char | 部分:DWARF typedef-bool 已修(boollit);**DTP 族 ❌** |
| C7 | NAME-NORM(GCC 后缀剥离) | H 后缀引用 0 vs D 10(`.constprop.0` 等) | 0/0 | headless demangler/分析器剥离 `.constprop/.isra/.cold` | ❌(小) |
| C8 | FUNC-DISC(函数发现) | H-only 50(1×FUN_ + 49×plt.sec) | H-only 1220(464 FUN_ + 756 named) | analyzer 发现无符号代码 + plt.sec 注册 | 部分:124-fn ledger 钉住门禁面;无需库侧桥 |
| C9 | PUSH-ABSORB | D 固定槽 push 29 行 | D 309 行 | DP 判例:headless 桥接层输入吸收;**预计随 C1/C3 落地自然收敛** | ❌(不单独建,跟踪 C1 效果) |
| C10 | SPILL-PAIR | D 19 行 | D 271 行 | FI 判例:**库级非缺陷**;headless 由 Java 分析器栈改变 merge/type-lock 输入所致,预计随 C1 落地观察 | 不单独建(FI 终局口径) |
| C11 | LABELS(LAB_/code_r) | H LAB_ 85 / D code_r 122 | H 2910 / D 1617 | Java DB 提供标号名 | ✅ EX2 |
| C12 | switchD 命名 | — | — | 同上 | ✅ GA/SMALLFIX |

已桥通道(C5/C11/C12 + C2 部分 + C3 部分)证明模式可行;**未建模主缺口 = C1(最大行质量)→ C2 → C3 → C4 → C6/C7(尾差)**。

## §3 通道归因的证据链(按 B2 口径)

每个通道的归因强度分三级:

1. **机制级(C++ 源码,锁定 oracle)** —— C1 的库内消费链已逐行核实:
   - `Funcdata::decode`(funcdata.cc:775-837):`<function>` 子元素 `<localdb>`(预填符号的 ScopeLocal)/`<override>`/`<prototype>`(锁定原型)/`<jumptablelist>`(预计算跳转表)—— **这就是 Java DecompInterface 与 C++ 库的全部接口**,驱动侧桥等价于在 Rust 侧重建同一协议的注入端。
   - `MapState::gatherSymbols`(varmap.cc:1044-1059):DB 符号以 `RangeHint::fixed` + typelock 进 restructure;Rugra 侧 varmap.rs:1950-1964 已逐行对应(本 lane 复核)。**播种 API 已在库内,缺的只是驱动侧喂数据。**
2. **差分级(双 golden)** —— §2 量化全部来自同源双 golden 对比;`local_` 0 vs 5824(direct vs headless)是 C1 存在性的直接观测。
3. **消融级(analyzer 开关)** —— **尚缺**:headless dist 当前不可用(重启丢失,HEADLESS_DIST_DEAD)。待重建后跑"关 Parameter ID / 关 Data Type Propagation"受控重导入,观测 `local_` 计数与 typed 声明变化,把 C1/C6 的 analyzer 级归因钉死(登记为 §5 W0 前置)。当前 analyzer 名称为最可能假设(证据:provenance risk 列表 + SPALIAS/GC 判例 + httpd stripped 反证 DWARF),非终局。

## §4 驱动侧通道设计(GD2/GJ 模式:数据从哪来/怎么注入/何时注入/怎么验证)

总原则(已验证先例的公共形态):**控制器(canon 模式)持有加料数据 → `DecompileRequest` 协议字段 → worker 在明确生命周期点安装 → mirror/bare 模式不加载(库级契约保持纯净)→ per-fn 差分门禁验收**。

### C1 TYPE-SEED-LOCAL(v1 主攻,详规见 §5)
- 数据从哪来: **golden 收割 manifest**(捕获侧,同 124-fn ledger 先例)—— 从 headless golden 的声明层收割每函数 committed locals(名字内嵌偏移 `local_c8`→-0xc8,类型串)。
- 怎么注入: worker 在 fd 构建后、`perform_action("decompile")` 前,经 `ScopeLocal::add_symbol_with_property`(varmap.rs:4041)安装 `(stack offset, name, type, typelock)`,类型经 `parse_c_type`(debugproto.rs,GL 已建,走 shared_default 工厂)。这是 **action 期种子**(区别于 GD2 的 print 期 DB):gather_symbols 在 NameVars/restructure 中段消费。
- 何时注入: action 前,一次性;镜像模式(投影/RUGRA_MIRROR)与 bare-load 不注入。
- 怎么验证: §5.5。

### C2 THUNK-GOT
- 数据: manifest 的导入函数签名表(name→proto)+ GOT 槽→`PTR_<name>_<addr>` 规则(.rela.plt 已有解析器,FIXTURE_CPP registerPltStubs 同源逻辑搬到 Rust 控制器——driver 已有 GOT PTR_ 标签半桥)。
- 注入: ①thunk 函数集:对 ledger 外的 PLT/plt.sec 条目按 `<prototype>` 锁等价路径锁 `funcp`(复用 C3 的 sig 安装);②thunk 标记→抑制 jumptable 恢复尝试:driver 侧对该地址集传 `jumptablelist` 等价物(空表+thunk flag)——若库侧无对应 seam 则登记 RUGRA-GAP 评估最小接入点(预期在 flow/jumptable 查询入口加 DB 查询,属既有 `ACTION-SYMDB-DATASYM-0001` 同族)。
- 验证: httpd 431 条 jumptable 警告→0;`PTR_` 372 全量符号化;per-fn 恒等校验。

### C3 SIG-LOCK 实函数
- 数据: golden 签名层收割(参数名/型/返回型 per fn);与现有 DWARF/libc 锁合流(已锁不动,未锁用 manifest 补)。
- 注入: 复用 `link_call_specs` 的 locked_proto 构建器(CALLSPEC-ENV-SCOPE-0001 资产),扩为 self-sig manifest 源。
- 验证: SIG/PARAM-NAME hunk 归零路径上的 per-fn 下降;`__x` 参数名计数对齐。

### C4 STRUCT-FIELD
- 数据: curl=DWARF composite(debugproto 已有 DWARF 类型通道,需组合类型 struct/field 语法扩展);httpd=FID 套型表(归因未钉死,先 curl)。
- 注入: 类型工厂注册真组合类型,替换 TYPEDEF_PREAMBLE 文本 hack;全局符号带类型(driver 全局图已有 DWARF-typed 半桥,补 composite)。
- 验证: STRUCT-FIELD/GLOBAL-SYM hunk 收敛;gcc 审计 URLGlob 族 FAIL 减少。

### C6/C7 尾差
- C6 BOOL-DTP:随 C1 类型播种大概率一并覆盖(bool 型在 manifest 内);残差单测。
- C7 NAME-NORM:控制器符号表剥离 GCC 后缀(1 行级映射, golden 对照 `parseconfig.constprop.0→parseconfig`)。

## §5 v1 规格 —— C1 类型播种(可实施)

### 5.1 数据产物: `tests/golden/manifests/local_seed_httpd_1204.json`(及 curl 版)
```json
{
  "oracle_commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
  "corpus": "httpd", "golden_sha256": "<文件哈希>",
  "harvest_rule": "decl-block lines matching '^\\s*(type)\\s+(local_[0-9a-f]+)(\\s*\\[\\d+\\])?;' before first statement; offset = -int(name[6:],16)",
  "functions": {
    "0x2ba90": { "name": "main", "locals": [
      {"offset": -0xd8, "name": "local_d8", "type": "long",  "typelock": true},
      {"offset": -0xd0, "name": "local_d0", "type": "long",  "typelock": true},
      {"offset": -0xc8, "name": "local_c8", "type": "long[4]", "typelock": true},
      {"offset": -0xa8, "name": "local_a8", "type": "undefined8 *", "typelock": true}
    ]}
  }
}
```
收割器 `tools/harvest_local_manifest.py`:解析 golden 函数块 → 首语句前声明块 → 正则取 `(type,name,array)`;只收 `local_[0-9a-f]+`(偏移内嵌,保守域);manifest 记录 oracle commit + golden sha256(机制 B2 口径)。**含 undefined-typed 的 committed locals 一并收割**(它们改变 restructure 分区与命名 auStack_→local_,是提交层的一部分);若 W1 门禁显示 undefined-typed 种子在 curl 引发回归,降级为 typed-only 子 manifest(决策门在验收内)。

### 5.2 协议: `DecompileRequest` 增 `committed_locals: Vec<CommittedLocal>`(`{offset: i64, name: String, type_expr: String}`)
canon 模式控制器从 manifest 装载(按 vaddr 匹配);mirror/bare 模式恒空。worker 协议版本号同步 bump(GJ 先例 v3→v4)。

### 5.3 worker 注入点(唯一 seam)
fd 构建完成(含现有 DWARF/模型锁)之后、`db.perform_action("decompile", &mut fd_write)`(curl_decompile.rs:4057)之前:
1. `parse_c_type` 逐条解析 `type_expr`(走 shared_default 工厂——GL 判例:类型身份域必须单一);
2. `fd.scope.add_symbol_with_property(stack 空间 offset, name, type, typelock=true)`(varmap.rs:4041;对应 C++ `decodeScope` 恢复的 symbol 随 `<localdb>` 入库);
3. 不触碰 funcp/寄存器参数(register 参数归 C3 域)。

库侧预期零改动:`gather_symbols`(varmap.rs:1950)与 restructure 消费链已对应 varmap.cc:1044/1260。若发现 Rust `add_symbol_with_property` 无法表达 EntryMap 预填(maptable 物化路径),允许 varmap.rs 最小 GLUE 补口(须 `// RUGRA-GLUE` 注释 + 机制 C 复核——varmap 是白名单模块)。

### 5.4 明确不做(边界)
- 不改 restructure/merge/type-lock 算法本体(SPALIAS 两 TODO 的"库内自举"路线让位于本桥:种子在库外,库保持与 direct-runner 契约)。
- 不播种寄存器参数/unaff_/extraout_(归 C3)。
- mirror 投影与五投影 bundle 必须字节恒等(不加载 manifest)。

### 5.5 验收门禁(v1)
1. **镜像纯净性**: RUGRA_MIRROR=1 五投影(next_url/match_url/parseconfig/getparameter/myprogress)字节恒等(MATCH×5 保持)。
2. **SPALIAS 定点**: httpd main 出现 `long local_c8 [4];` + `long local_d0; long local_d8;` 声明与 `plVar = local_c8` 直接符号形(SP 族 40 行残差显降,目标 ≤ 个位数;绑定 VARMAP-SPALIAS-RETYPE-0001 验收)。
3. **E2E**: curl/httpd 差分 defects=0/numbering=0 保持,skeleton 下降(httpd 预期 −500 以上量级:5824 引用层的声明/形态收敛),per-fn 零回退(允许改善)。
4. **确定性**: 双跑 byte-identical。
5. **机制 B2**: harvest manifest 内函数逐个与 golden decl 层 fixture 对拍(收割器自校验);Rugra seeded-run vs golden 块:decl 层目标 MATCH,body 层差异如实登记(归后续 C2/C3)。
6. gcc 审计 fail 集不新增。

### 5.6 风险与开放项
- **风险 R1**: committed locals 与 DWARF 自原型锁(param 溢出槽)的窗口重叠 → 验收 3 的 per-fn 门禁捕捉;必要时 manifest 收割时排除 param 槽区间(funcp local window 已有范围)。
- **风险 R2**: undefined-typed 种子引发 curl 回归 → §5.1 决策门(typed-only 降级)。
- **风险 R3**: analyzer 级归因未终局(W0 消融缺 headless dist)→ manifest 是"捕获侧真值",机制归因开放不影响 v1 可实施性;W0 补消融后再定 C6 是否独立通道。
- **开放 O1**: httpd STRUCT-FIELD(26 hunk)在 stripped 下的类型来源(FID 套型?)—— W2/W4 时用 headless dist 消融钉死。

## §6 分波排期

| 波 | 内容 | 前置 | 预期主收益 |
|---|---|---|---|
| **W0**(可并行) | HEADLESS-BRIDGE-ATTRIB-0004:重建 headless dist;analyzer 开关消融(Parameter ID commit-locals / Data Type Propagation / FID)重导入 curl+httpd,钉 C1/C6 analyzer 归因;抓 `<localdb>` XML 真值交叉验证 manifest | 无(纯捕获侧) | 归因 NO_ORACLE→MATCH;manifest 交叉验证 |
| **W1(v1 核心)** | HEADLESS-BRIDGE-V1-TYPESEED-0001:harvester + manifest + 协议字段 + worker 播种 + §5.5 全门禁;httpd 先行(最大行质量+SPALIAS 既有判决) | 无(不依赖 W0) | httpd `local_` 层 5824 引用建模;SPALIAS 定点;C9/C10 观察 |
| W1b | curl roll-in(117 引用 + DWARF 名局部 `urls/urlnum` 同机制;含 NAME-NORM 顺带 3 hunk) | W1 | curl C1+C7 |
| W2 | C2 THUNK-GOT(导入签名 manifest + thunk 标记/警告抑制) | W1(复用 manifest 框架) | httpd 431 jumptable 警告→0;THUNK-PAIR 495 hunk |
| W3 | C3 SIG-LOCK 补全(real-fn 签名 manifest 合流 link_call_specs) | W1 | SIG 418 + PARAM-NAME 146 hunk(httpd) |
| W4 | C4 组合类型(替换 TYPEDEF_PREAMBLE hack)+ C6 残余 + O1 归因 | W0 | STRUCT-FIELD/GLOBAL-SYM hunk;gcc 审计 |

v1 交付判据 = W1(+W1b)全绿;每波独立 commit、独立 per-fn 零回退证明。

## §7 与既有登记的关系

- `VARMAP-SPALIAS-RETYPE-0001`:v1 验收直接绑定其验收点(`long local_c8[4]` 等);**路线变更**:库内自举(STORE 值反压/多轮往返)→ 驱动播种(种子已证在库外,SPALIAS drill)。lane GK 移交注记保留。
- `RULEACTION-SPALIAS-INDIRECTPTR-0002`:独立(INDIRECT 传型链),不随 v1 收口,维持排队。
- `MERGE-COPYNOISE-SPILLRESTORE-0001`(FI 终局)/`GOLDEN-CONTRACT-PUSHABSORB-0001`(DP):C10/C9 的观察哨——W1 落地后重测 spill 对/push 行是否随之收敛,并在各自 TODO 行回写结论。
- `ACTION-SYMDB-DATASYM-0001`(SMALLFIX ③):C2 的 jumptable/thunk DB 查询接入点同族,W2 时合并考量。

## §8 复现实验(本 lane 产物留档)

```bash
# 通道量化(全部产物在 /dev/shm/rugra-tests/bridge1/)
python3 /dev/shm/rugra-tests/bridge1/parse_golden.py tests/golden/ghidra_curl_1204.c tests/golden/ghidra_curl_1204.direct-runner.c 0x100000
python3 /dev/shm/rugra-tests/bridge1/diff_hunks.py tests/golden/ghidra_httpd_1204.c tests/golden/ghidra_httpd_1204.direct-runner.c 0x100000 /tmp/httpd_hunks.json
# 机制源码锚点:funcdata.cc:775-837(<function> 协议) / varmap.cc:1044-1059(gatherSymbols) / varmap.rs:1950,4024,4041(Rust 消费+播种 API)
# grep 口径行数:local_/PTR_/pcRam/LAB_/code_r/jumptable warn/locked warn/.constprop(见 §2 表)
```

---

## §9 W1 交付记录（Lane BRIDGE1，2026-09-25，基=亲父 b255cce9）

### 9.1 步骤① 通道内容 oracle 判定：**证实**

仪器化方法（复用 RANGEHINT lane 的 git-archive 锁定库构建链）：新增
`stage_seed_diag.cc`（/dev/shm/rugra-tests/bridge1/，构建=build_seed_diag.sh）——
BfdArchitecture 裸加载 + 在 fd 解析后、followFlow 前把种子 XML 喂给
`fd->getScopeLocal()->decode(decoder)`（**真实 `<localdb>` 协议链**：
ScopeInternal::decode → Scope::addMapSym → Symbol::decodeHeader(typelock/
namelock) + decodeType + SymbolEntry::decode(`<addr>`+`<rangelist>）→ addMap），
然后按 golden 生成器契约驱动 + PrintC docFunction。

锁定 oracle 库 + httpd main 种子（§5.1 收割清单）输出
（/dev/shm/rugra-tests/bridge1/oracle_main_seeded.c）：

- **声明层逐符号复现 canon**：`long local_d8; long local_d0; long[4] local_c8;
  undefined8 *local_a8; undefined8[2] local_80; long[6] local_70; undefined8
  local_40` + 未提交块 `axStack_9c [7]`——92B hermetic 整块被种子切成
  28B+16B+48B，分区与 canon 一致（RANGEHINT 判定的"1B 反馈环"被 fixed
  typelock hint 打破）。
- **下标形族复现**：133 处 `plVar11[-N] =`（canon main 134 处；
  hermetic 库为 0——`*(xunknown8*)((int8)p + -8)` 形）。
- **证伪边界**：canon 的 15 处 `local_d0 = <retaddr>;` 直接赋值拼写连
  seeded-oracle 也不产生（打印为 `plVar11[-1] = <retaddr>`，同一存储的
  别名指针形）⇒ 该族需要种子之外的 headless 状态（Parameter ID 早轮
  IR/别名挂接差异），**超出 C1 v1 范围**，归 HEAD 残差（W0 消融可再钉）。

### 9.2 as-built 与 §5.2/5.3 的偏差（按实测修正）

- 种子载体：`Funcdata::committed_locals: Vec<CommittedLocal>`
  （funcdata.rs，RUGRA-GLUE）而非 `DecompileRequest` 协议字段——httpd
  驱动是单进程线程模型，无 worker 协议可 bump；fd 字段即
  `<localdb>` 载体的 Rust 形态。
- 注入点：`ActionRestructureVarnode::apply` 的 scope 首次构造臂
  （coreaction.rs，平台参数符号安装之后）而非"驱动在 perform 前
  ScopeLocal::add_symbol"——Rugra 的 ScopeLocal 是首个 restructure
  pass 才惰性构造的（fd.scope=None），None 臂构造点正是 oracle
  "Funcdata 构造 → localdb decode → action" 生命周期的镜像位。
  类型解析走 `parse_c_type`（debugproto.rs，扩展数组声明符+C1 基
  类型表，shared_default 工厂保持类型身份域单一）。
- opt-in 门：`RUGRA_TYPESEED=1`（`RUGRA_TYPESEED_MANIFEST` 可覆写路径，
  默认 `tests/golden/manifests/local_seed_httpd_1204.json`，按
  vaddr+0x100000=canon 地址匹配）；mirror 门下恒不装载（五投影纯净
  性）。默认路径 committed_locals 恒空 ⇒ 输出与亲父 cmp 字节恒等。
- 附带修复：prettyprint 声明回填 pass 现在识别后缀数组声明符
  （`long local_c8 [4];` 旧实现在 declared 集里记下 `[4]` 而非
  `local_c8`，回填注入了 `int local_c8;` 重复声明）。
- v1 域收缩：收割器跳过结构体基类型种子（sigaction/sigset_t 各 1，
  C4 组合类型域）；curl 侧 W1b 未并入（curl golden 局部名以 DWARF
  语义名为主，local_ 保守域只收 4 函数/18 条，收益小，留 W1b 专项）。

### 9.3 W1 验收（亲测，基=亲父 b255cce9）

| 门禁 | 默认（无 env） | opt-in（RUGRA_TYPESEED=1） |
|---|---|---|
| httpd E2E canon | **1472/0/0**，cmp 亲父字节恒等 | **1360/0/0**（−112） |
| curl E2E canon | **1099/0/0**（=亲父） | n/a（httpd manifest） |
| 五投影银行 | **26/26 MATCH** | mirror 门恒不装载 |
| cargo test --lib | 1709P/1F（预存 VHOST） | 同 |
| 双跑确定性 | cmp 恒等 | cmp 恒等 |

逐函数（6 个被播种函数全部改善、0 回退）：main 694→668；
ap_parse_vhost_addrs 27→9；ap_fini_vhost_config 245→218；
ap_update_vhost_from_headers 92→71；ap_ht_time 17→13；
ap_os_is_path_absolute 23→7。

main 族前后（vs canon）：local_* 引用 0→11（canon 44；**seeded-oracle
同为 11**——C1 域内 Rugra==oracle）；auStack/uStack 命名 11→3（canon 4；
oracle-seeded 同 3）；下标形 119（canon 116，oracle-seeded 133——差 14
为既有库级 typeprop 域，非 C1 引入）；字符串族 0（canon 81）不动——
C5-邻域，非 C1 目标。SPALIAS 定点（§5.5-2）：`long local_c8 [4]`/
`local_d0`/`local_d8` 声明全量出现 ✓；`plVar = local_c8` 直接符号形 ✓
（canon 的 `local_d0 = retaddr` 15 处拼写族按 §9.1 证伪边界豁免）。

## §10 W1b 交付记录（Lane W1B，2026-09-25，基=亲父 1de6dd39=master TYPEFIX 后）

curl 语料卷入：manifest 入库 + curl 驱动 opt-in 门，**零 src/ 改动**
（BRIDGE1+TYPEFIX 后库侧通道在位，本波纯驱动/数据域）。

### 10.1 manifest（`tests/golden/manifests/local_seed_curl_1204.json`）

- harvest：BRIDGE1 方法原样（`tools/harvest_local_manifest.py` over
  `tests/golden/ghidra_curl_1204.c`，oracle commit e40ed130 + golden
  sha256 指纹齐备）——**3 函数 / 16 种子**：main 1（`int local_230`）、
  helpf 13（`undefined1 local_b8[8]` + 12×`undefined8 local_*`）、
  parseconfig 1（`char *local_160`）。
- KNOWN_BASES 剔除生效：getparameter 的 `Configurable *local_5b8` /
  `HttpPost *local_5a8`（结构体指针基，post-TYPEFIX parse_c_type
  no-fallback bail ⇒ 若入库即为死条目，harvest 同逻辑剔除）；golden
  内 18 个 distinct local_ 名全部归账（16 收 + 2 剔）。
- 域边界（与 §9.2 一致）：curl golden 的具名 local 以 DWARF 语义名为主
  （urlnum/urls/outs/heads/usedarg/filebuffer/ap(va_list) 等），名字不
  内嵌偏移 ⇒ 保守 local_ 域不收（DWARF-named 扩展 = 独立后续 lane，
  需 .debug_loc 位置表 fbreg→stack 偏移换算 + W0 `<localdb>` XML 交叉
  验证；getparameter 结构指针基依赖 C4 组合类型通道）。

### 10.2 驱动接线（`examples/curl_decompile.rs`，镜像 httpd 侧门）

- `RUGRA_TYPESEED=1`（`RUGRA_TYPESEED_MANIFEST` 覆写路径，默认
  `tests/golden/manifests/local_seed_curl_1204.json`）→ worker 进程
  `decompile_request` 在 fd 构建后、perform_action 前把 canon 地址键
  （vaddr+0x100000）的种子挂到 `fd.committed_locals`（`<localdb>`
  transport 位；worker 子进程继承控制器 env ⇒ 同门；原型 pre-pass
  永不播种——镜像 httpd 只在反编译线程播种的边界）。
- OnceLock 每进程一次装载；**默认路径构造性恒等**：env 未设 →
  无 manifest IO、committed_locals 恒空，亲父 cmp 字节恒等（实测）。
- 镜像门恒不装载：任一 mirror 分量（RUGRA_MIRROR/RUGRA_FLOW_MIRROR/
  RUGRA_BARE_LOAD/RUGRA_ORACLE_FIXTURE_DATA）在场即拒绝并告警；
  实测 RUGRA_MIRROR=1+TYPESEED=1 输出与纯 mirror 运行 cmp 恒等。

### 10.3 W1b 验收（亲测，基=亲父 1de6dd39）

| 门禁 | 默认（无 env） | opt-in（RUGRA_TYPESEED=1） |
|---|---|---|
| curl E2E canon | **1099/0/0**，cmp 亲父字节恒等 | **1054/0/0**（−45） |
| httpd E2E canon | **1472/0/0**（=亲父，例程未触碰） | **1360/0/0**（=BRIDGE1 见证复现） |
| 投影银行 | —（frozen 钉） | mirror 门恒不装载 |
| gcc 审计 | 103 OK/21 FAIL | fail 集逐名相同（零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 |

逐函数（全部改善、0 回退；121 个未播种函数字节恒等）：main 212→206、
helpf 75→50、parseconfig 73→59。播种函数零回退硬门 ✓。

−45 vs 目标 −50 的差额归因（域内无可收余量）：helpf 余 50 =
va_list ap typedef 族（DWARF-named 域）+ 寄存器溢出赋值吸收族
（库级 typeprop 域，与 §9.3 下标形残差同族）+ `&stack0x8` 拼写；
parseconfig 余 59 = usedarg/filebuffer（DWARF-named bool）+ 临时编号
偏移 + 字符串常量形（C5-邻域）；main 余 206 = urlnum/urls/outs/heads/
progressbar/fileinfo/errorbuffer（DWARF-named/结构体域）。

## §11 C2DWARF 交付记录（Lane C2DWARF，2026-09-25，基=亲父 36d5efb6）

W1b 差额归因指认的 DWARF-named 域（curl −45 的余额大头）落成：C1 通道的
DWARF 语义名扩展（名字来自 .debug_info，位置来自 inline DW_OP_fbreg，
经 `<localdb>` 种子运输）。**零 src/ 改动**（机制 C 工具/驱动域豁免：
tools/harvest_local_manifest.py 扩展 + manifest + examples 门）。

### 11.1 oracle 级预验证（先行，BRIDGE1 方法论照做）

仪器化：`stage_seed_diag`（锁定库 e40ed130，真 `<localdb>` decode 链）+
pyelftools 全量 DWARF 盘点（/dev/shm/rugra-tests/c2dwarf/，21 条
exprloc-fbreg 条目/9 函数）→ 按规则构造种子 XML → 逐函数 seeded/unseeded
对照 canon：

- **声明层逐名复现**：6 函数全部命中——main `int urlnum; bool[256]
  errorbuffer`、myprogress `char[40] format; bool[256] line; bool[256]
  outline`、my_get_line `bool[4096] buf`、file2string `bool[256] buffer`、
  parseconfig `bool usedarg; bool[256] filebuffer`、getparameter
  `time_t now`；下标形/`== true` 体形态同步复现。
- **fbreg→偏移换算钉死**：offset = fbreg(N)+8（frame_base=
  call_frame_cfa=CFA=RSP_entry+8，Ghidra stack 0=RSP_entry 槽）；机码级
  校准 urlnum fbreg(-0x22c)→`cmpl 0x34(%rsp)`→-0x224、errorbuffer
  fbreg(-0x150)→`lea 0x110(%rsp)`。
- **canon-committed typing 判决**：DWARF 说 char[256]/[4096]，canon 打印
  bool——char 种子（--dwarf-raw-types 形态）不匹配 canon decl，bool 种子
  匹配 ⇒ Java 分析器提交层把 boolean 用途的 char 数组重定型为 bool
  （C6 DTP 族交叠），manifest 取 canon-committed 形态。
- **sec_offset 域判决**：canon 从不为 loc-list 变量命名（main 的
  i/res/url/infd/... 全部无名）⇒ Ghidra DWARF importer 丢弃 loc-list，
  harvest 同域排除（防 over-seed）。
- **邻接吸收判决（file2string）**：仅 seed `buffer bool[256]` 时锁定
  oracle 也产出 `bool abStack_150[8]`（数组吸收未提交邻槽）——canon 保持
  `undefined8 uStack_150` 独立 ⇒ canon 的提交层含该合成槽（C1 无名提交）；
  buffer+uStack_150 双种子下 oracle 复现 canon 分区 ⇒ harvest 增加
  canon-decl 邻接采纳规则（source=canon-decl 标注）。
- **槽主规则**：main -504 槽首声明 progressbar（struct，C4 残差）⇒
  passarg（bool，后声明）canon 从不打印 ⇒ 首声明拥有槽，不可服务首声明
  连带遮蔽后续同槽可服务者。

### 11.2 manifest 与装载

- `tests/golden/manifests/local_seed_curl_1204_dwarf.json`：6 函数/11 种子
  （10 DWARF + 1 canon-decl 邻接守卫 uStack_150）+10 drops 全归账；指纹
  齐备（oracle e40ed130 + binary sha256 + golden sha256 aca37988 实测
  复核）；harvest_rule 全规则留档。
- `examples/curl_decompile.rs`：`RUGRA_DWARFSEED=1`（+
  `RUGRA_DWARFSEED_MANIFEST` 覆写，默认上述路径）独立门——与 W1b
  `RUGRA_TYPESEED` 门共享 `load_committed_local_manifest` 解码器但 env
  独立 ⇒ **TYPESEED=1 单开保持 W1b 见证字节恒等**（归因可分）；attach
  在 TYPESEED 之后 extend committed_locals（偏移碰撞 = manifest 缺陷，
  响亮告警）；mirror 四分量在场恒拒载（实测 RUGRA_MIRROR+双门输出与纯
  mirror cmp 恒等）；默认路径构造性恒等（无 manifest IO）。

### 11.3 C2DWARF 验收（亲测，基=亲父 36d5efb6）

| 门禁 | 默认（无 env） | TYPESEED=1 | TYPESEED=1+DWARFSEED=1 |
|---|---|---|---|
| curl E2E canon | **1099/0/0**，cmp 亲父字节恒等 | **1054/0/0**，cmp 亲父字节恒等（W1b 见证保持） | **944/0/0**（−110） |
| 投影银行 | 71/71 PASS（离线，frozen） | mirror 门恒闭 | mirror 门恒闭（实测拒载） |
| gcc 审计 | 103 OK/21 FAIL（=亲父） | 同 | **104 OK/20 FAIL**（my_get_line 修复，零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 | cmp 恒等 |

逐函数（TYPESEED→双门，**0 回退**硬门 ✓；118 未播种函数字节恒等）：
main 206→186、myprogress 33→15、my_get_line 30→16（gcc FAIL 同步修复）、
file2string 76→39（邻接守卫）、parseconfig 59→39、getparameter 385→384、
helpf 50→50（未触碰）。

### 11.4 残差登记（不可经本通道复现 → HEAD/C3/C4 域）

main `URLGlob *urls`（C4 pointee）/`OutStruct outs,heads`/`ProgressData
progressbar`（+passarg 槽遮蔽）/`stat fileinfo`/canon-only `URLGlob glob`
（inlined glob_url 参数，C3+C4）；helpf `va_list ap`（typedef→struct，C4）；
getparameter `stat statbuf`/`LongShort aliases[50]`（C4）；match_url
`URLGlob glob`（栈参数，C3）；全部 sec_offset loc-list 变量（Ghidra 自身
丢弃）。C4 组合类型（V4-W4）与 C3 签名锁（V3-W3）是这些残差的归属通道。

## §12 C3NEXT 交付记录（Lane C3NEXT，2026-09-25，基=亲父 5fff5592）

通道选择判决：§11.4 的 11 个不可复现族中 **8 个属 C4**（urls/outs/heads/
progressbar+passarg/fileinfo/ap/statbuf/aliases + canon-decl local_5b8/
local_5a8），仅 glob×2 属 C3；且 getparameter 384 与 main 186 残差主体为
结构体声明层+字段形族。**选 C4 STRUCT-SEED**。写域=tools/harvest_local_
manifest.py（--struct 模式）+tests/golden/manifests/local_seed_curl_1204_
struct.json+examples/curl_decompile.rs（RUGRA_STRUCTSEED 门，镜像 C2DWARF
形态）+docs；**src 触碰 1 处（声明）**：src/debugproto.rs（OUTSTRUCT-ID0
身份修复，独立 commit bcaaf396，机制 C 白名单外——debugproto 非
heritage/jumptable/blockaction/condexe/varmap/merge 域；printc.rs/varmap.rs
全程未触碰）。

### 12.1 oracle 级预验证（先行，BRIDGE1 方法论照做）

stage_seed_diag（锁定库 e40ed130，真 `<localdb>` decode 链）+ pyelftools
DWARF 盘点（/dev/shm/rugra-tests/c3next/：struct_inventory.py /
dwarf_types.py / gen_struct_seed_xml.py + seed_*.xml + oracle_*_seeded.c）：

- **DWARF 盘点**：结构体变量 9 条（main urls/outs/heads/progressbar/
  fileinfo+passarg 同槽、getparameter statbuf/aliases、helpf ap）+
  match_url glob 为 fbreg(0) 栈形参（C3 域，不收）。
- **声明层逐符号复现（3/3 函数全命中）**：main `URLGlob * urls; OutStruct
  outs; OutStruct heads; ProgressData progressbar; stat fileinfo;`；
  getparameter `Configurable * local_5b8; HttpPost * local_5a8; stat
  statbuf; LongShort[50] aliases;`；helpf `va_list ap;`。
- **字段形族复现**：`outs.stream/outs.filename/heads.stream/heads.filename`
  读写、`fileinfo.st_size`、`progressbar.total`、`glob_url(&urls,...)`/
  `next_url(urls)`、getparameter 别名环 `->letter/&->lname`。
- **va_list 域判决**：typedef 折叠为 struct 时 oracle 打印 `ap.field` 且
  按 `&ap` 传递；**数组形**（`__va_list_tag[1]` 命名 va_list）时打印
  `ap[0].field` 且按值传递 `ap`——canon 为数组形 ⇒ 种子必须以数组形
  运输（gen_struct_seed_xml 的 typedef→array 链修复即此判决）。
- **已知 harness 工件（非语义差异）**：种子态 oracle 打印抽象数组形
  `bool[256] errorbuffer`/指针间距 `URLGlob * urls`，canon 打印声明符形
  `bool errorbuffer [256]`/`URLGlob *urls`——C2DWARF 判例同款（Java 导入
  器构建的类型对象形态差异）；Rugra 侧独立以 canon 形输出（E2E 实证）。
- **指针型选举（getparameter 别名环）**：裸 oracle 里 LongShort* 胜出
  （`pLVar6->letter`），canon 为 Configurable*（`pCVar13->useragent`）；
  Rugra 全驱动（funcp 的 Configurable* 参数锁在场）落 canon 形 ✓。

### 12.2 实现形态

- **manifest** `tests/golden/manifests/local_seed_curl_1204_struct.json`：
  3 函数/10 种子（main 5 DWARF + helpf 1 + getparameter 2 canon-decl +
  2 DWARF）+12 drops 全归账 + residual_notes 5 条（glob×2/register var
  `Configurable *config`/sec_offset 域/Unresolved 注释族）；指纹齐备
  （oracle e40ed130 + binary sha256 + golden sha256）；harvest_rule 全
  规则留档。
- **harvester** `--struct` 模式：DWARF 复合体命名域（可直接命名的
  structure/union/enum + typedef over composite/array）为准入门（TYPEFIX
  规矩的 C4 等价物：未知命名基=工厂名树 None=死条目，剔除）；KNOWN_BASES
  域显式排除（C1/C2 通道属地，按构造不相交）；首声明槽主规则（progressbar
  遮蔽 passarg）延续；canon-decl 采纳=local_[hex] 声明 + 结构体指针基。
- **驱动门** `RUGRA_STRUCTSEED=1`（+`RUGRA_STRUCTSEED_MANIFEST` 覆写）：
  与 TYPESEED/DWARFSEED 同装载器、独立 env；attach 在 DWARFSEED 之后，
  偏移碰撞=响亮 manifest 缺陷告警；mirror 四分量在场恒拒载（实测
  RUGRA_MIRROR+三门输出与纯 mirror cmp 恒等）；默认路径构造性恒等。
- **src 前置（bcaaf396）**：intern_named 的 id=hashName 派生（type.cc:675
  镜像）+ 零尺寸不完整复合体守卫 + parse_c_type 名树 findByName 回退
  （grammar.cc:2989 镜像）——直接命名复合体（OutStruct/stat/...）此前
  从未进名树（id=0 被 find_add 拒绝后静默未注册），typedef 路径不受影响。

### 12.3 C3NEXT 验收（亲测，基=亲父 5fff5592 + bcaaf396）

| 门禁 | 默认（无 env） | TYPESEED=1 | TYPESEED+DWARFSEED | 三门全开 |
|---|---|---|---|---|
| curl E2E canon | **1096/0/0**（=bcaaf396 见证；亲父 5fff5592 为 1099，差额 −3 归因见 bcaaf396 Differential） | 1051/0/0 | **941/0/0** | **767/0/0**（−177 vs 亲父双门） |
| 投影银行 | 71/71 PASS（离线，frozen） | mirror 门恒闭 | mirror 门恒闭 | mirror 门恒闭（实测拒载+cmp 恒等） |
| gcc 审计 | 104 OK/20 FAIL | 同 | 104 OK/20 FAIL | **104 OK/20 FAIL**（fail 函数名集与双门态逐名相同，零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 | cmp 恒等 | cmp 恒等 |

逐函数（双门→三门，**0 回退**硬门 ✓；14 个未播种函数字节恒等）：
main 185→**129**（−56）、getparameter 382→**277**（−105）、helpf 50→**37**
（−13）。字段形实证：`outs.stream = stdout`/`outs.filename = ::config.outfile`/
`fileinfo.st_size`/`progressbar.total`/`ap[0].gp_offset`/`LongShort
aliases [50]`（canon 数组拼写形）全量出现；getparameter 别名环指针选举落
canon 形（`pCVar13 = (Configurable *)aliases; ... ->useragent`）。

### 12.4 残差登记（不可经本通道复现 → HEAD/C3 域）

- main `URLGlob glob` 槽位发现（canon-only inlined 参数，DWARF 无 location；
  双门态 decl 已在但槽位归属未钉）→ C3 域。
- match_url `URLGlob glob` 栈形参（fbreg(0) 正槽）→ C3 原型锁域。
- main `Configurable *config` 寄存器变量（无栈槽；canon decl 在场=驱动
  DWARF 层产物）→ localdb register-symbol 域（HEAD）。
- canon `/* Unresolved local var */` 注释块（Java 前端工件，decompile/cpp
  无该串；main 3 行+getparameter ~20 行）→ 注释通道域。
- getparameter/main 计数器分型（`for (var_8; ...)` vs `for (lVar11 =
  0x96; ...)`）与 canary 声明位/编号级联 → 库级 typeprop/merge 域
  （与 §9.3 下标形残差同族）。
- sec_offset loc-list 全域（Ghidra importer 自身丢弃，预登记）。
