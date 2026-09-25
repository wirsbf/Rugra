# CURLATTR 车道终报 — curl canon 残差全量新鲜归因 @ master efc28f4a（2026-09-26, CURLATTR 只读车道）

> oracle = Ghidra 12.0.4 锁定 commit e40ed130。golden = `tests/golden/ghidra_curl_1204.c`（canon/headless 口径）。
> 本车道零 `src/` 改动;全部测量/分类产物在 `/dev/shm/rugra-tests/curlattr/`（重启即丢,结论与复现命令已录本文）。
> worktree = /dev/shm/rugra-worktrees/curlattr（wt/curlattr,基=master efc28f4a = PKGG 合并点）。

## 0. 口径勘误：种子数字已被后续车道消化

派单种子 vs 本车道新鲜实测（同一基线 efc28f4a,CARGO_TARGET_DIR=/dev/shm/rugra-targets/curlattr,fast-release）:

| 种子 | 派单说法 | 实测 |
|---|---|---|
| curl canon 总量 | ~267/0/0（ENVDAT 后） | **267/0/0 复现**（124/124 matched,双跑 cmp 恒等,stdout sha256 `c0610164058d43ae…`） |
| getparameter | ~43 行 | **37 行**（ENVDAT −2 + INTSUFFIX −1 + DWARFBASE −1 + 后续车道 −2 已消化） |
| glob_word | 5 行 | **0 行**（CASEWRAP/GLOBATTR/SWGOTO 链已全收敛——种子过期） |
| ap_ht_time | 1 行 | **不在 curl 语料**（httpd 函数;CALLOTHER-OUTTOKEN=PRINTCS 在飞 wt/printcs e8b6ec5e,覆盖面为 httpd） |

复现命令:

```bash
CARGO_TARGET_DIR=/dev/shm/rugra-targets/curlattr cargo build --profile fast-release --example curl_decompile
/dev/shm/rugra-targets/curlattr/fast-release/examples/curl_decompile > /tmp/curl.c 2>/dev/null
python3 tools/compare_ghidra.py /tmp/curl.c tests/golden/ghidra_curl_1204.c --summary-only
# → Total skeleton diff lines: 267 / defects 0 / numbering 0 / matched 124
python3 /dev/shm/rugra-tests/curlattr/full_diffs.py <rugra.c> <golden.c> <outdir>   # 全函数无截断骨架 diff
python3 /dev/shm/rugra-tests/curlattr/classify.py                                  # 逐行分族表
```

## 1. 残差全量分布（267 行,15 函数）

| 函数 | 行数 | 函数 | 行数 |
|---|---|---|---|
| main | 88 | myprogress | 7 |
| getparameter | 37 | __libc_csu_init | 7 |
| file2string | 31 | _start | 6 |
| helpf | 29 | my_get_line | 6 |
| my_get_token | 20 | next_url | 4 |
| parseconfig | 18 | glob_set | 3 |
| _init | 8 | progressbarinit / glob_range | 2 / 1 |

（其余 109 函数 skeleton identical。）

## 2. 分族总表（手工合并 ±line 对侧后锁定;机器表见 §8）

排序按行数。**"票况"列 = 新立票（§5）或既有票交叉引用（§3）**。

| 族 | 行数 | 主函数 | 根因一句话 | 域 | 票况 |
|---|---|---|---|---|---|
| **D. union store 仲裁** | 46 | main | `.content = (anon_union)V._8_16_` vs `.content.Set = (union_5a7)V._8_16_`——9 处 glob 初始化 store 的 union 字段下降深度:oracle 停在 union 成员整存,Rugra 一律下降到 `.Set`;oracle 同函数另 1 站点（golden:746）**确实**下降到 `.content.Set.elements`（两侧同形）→ 非 downChain 硬规则差,是**逐站点解析仲裁差**（ScoreUnionFields/resolveInFlow 决策面） | unionresolve+printc | **新票 P1** |
| **A. 原型驱动实参/存储 cast** | 45 | main 31 / gp 9 / my_get_line 2 / parseconfig 2 / file2string 1 | `(FILE *)fp`/`(stat *)&fileinfo`/`(FILE *)fopen(...)`/`return(char *)x` 族:golden 对锁定原型指针参数（FILE\*/stat\*）与 FILE\* 值侧一致插 cast;Rugra 不插（或对向）——castInput/castStandard 对 struct 指针参数的插入决策 | typeop/coreaction setcasts | **新票 P1** |
| **B. helpf varargs 保存链** | 29 | helpf | `in_AL/in_XMM0-7_Qa` 13 声明 + `if(in_AL) {local_88=in_XMM0…}` 8 行 + `local_b0=in_RSI` 5 行:整条 varargs 寄存器保存链缺失 | condexe/fspec | **既有票 HELPF-VARARGS-SAVECHAIN-0001(2026-09-01 车道死,需复活)** |
| **C. bool 元类型族** | 29 | main 8 / gp 8 / file2string 6 / myprogress 4 / my_get_line 3 | ①`== false` vs `== '\0'`（`::config.remotefile` 等 DWARF `typedef char bool` 字段,oracle 按名解析 typedef `bool`→正典 bool 元类型,Rugra 保持 char）;②对向 `(bool *)buffer` 多余 cast（golden 同名 pbVar 无 cast=castStandard 同尺寸 pointee 指针免 cast 规则）;③`(bool)(x^1)` 缺失 | debugproto/cast | **新票 P2**（②部分与 F-TYPE-FEED 重叠,见 §3） |
| **E. 静态作用域符号名** | 22 | my_get_token 18 / next_url 4 | `my_get_token::save`/`next_url::beenhere`（golden）vs `save`/`beenhere`（Rugra）。**根因已钉死（本车道源码级）**:worker 内 `build_worker_architecture` 的 legacy DWARF 种子层（curl_decompile.rs:3847）用**未限定** `global.name` 先插入 DB;前端通道的限定名层（:5585 `dwarf_display_names`,qualified）后插成**重复符号**;查询取先插者 → 裸名胜出。GLOBWORD-C5 注释自述过同型危害（重复条目赢 queryContainer smallest-pick） | examples 驱动 | **新票 P1（一行级修复）** |
| **F. getparameter 局部类型仲裁** | 24 | gp 21 / main 3 | golden 的复用局部是 `Configurable *`（`(Configurable *)fopen(...)`/`V != (Configurable *)0`/`(Configurable *)stdin` 各用点带 cast）;Rugra 同组局部定型 `FILE *` → 对向差。varmap 高类型/typeprop 仲裁 | varmap/coreaction | **新票 P2** |
| **G. \_\_stream 名推荐** | 12 | parseconfig | golden `FILE *__stream`（fclose libc 原型参数名推荐,coreaction.cc:2853-2897 lookForFuncParamNames）;Rugra `fp`（**my_get_line 的 DWARF 参数名**优先了）——多被调推荐参与集/覆盖序分歧 | coreaction/varmap | **新票 P2** |
| **H. image-base 显示** | 7 | file2string | `uStack_150 = (undefined *)0x103af8` vs `0x3af8`(×6)+`&UNK_00103c47` vs `0x3c47`(×1):retaddr 槽常量为代码地址,canon 以 0x100000 载入 golden 全带增量 | printc/驱动载入 | **既有票 HTTPDMAIN-F2-IMAGEBASE-0001 的 curl 位点**（V4/V5 决策挂起中） |
| **I. 声明区漂移** | 8 | glob_set 3 / gp 2 / _init 1 / main / glob_range / file2string 各 1 | `short V` vs `char *V`×2、`FILE *V` 换位等——纯计数/次序,大多是 A/C/F 族的声明面投影 | varmap | **既有票 MIRATTR-F-DECL-0001 同域**（curl 位点并入） |
| **J. \_init/csu 原型恢复** | 11 | _init 7 / csu 4 | golden `int _init(EVP_PKEY_CTX *ctx)`/`__libc_csu_init(EVP_PKEY_CTX*,…)`——EVP_PKEY_CTX 全二进制/DWARF/驱动 0 出现（亲证 grep=0）,纯 analyzeHeadless 分析器知识（FID/签名库） | headless 桥接数据 | **新票 P3** |
| **K. 入口 unaff 过参** | 4 | _start | golden 2 参 + 第 2 实参 `V`;Rugra 3 参 + `undefined8 unaff_retaddr;` 声明 + 实参 `unaff_retaddr`——entry thunk 的 retaddr 被 heritage 提升为 unaffected 输入并进默认参数发现 | heritage/fspec | **新票 P3**（MIRATTR-F-UNAFF 同族异位点） |
| **L. 字段/数组下标形** | 5 | progressbarinit 2 / file2string 3 | `bar->field_LIT` vs `*((long)bar + LIT)`;`buffer._0_4_` vs `buffer[LIT]._0_4_`——typed 指针字段解析/数组元素粒度 | typeprop/varmap | 部分挂 RULEACTION-STACKIDX-FOLD/ADDRSLOT 谱系,**新票 P3** |
| **M. for↔while 拆分** | 4 | file2string 4 | findLoopVariable 整体缺失（main 的 for 族行已计入 F,Hunk 混排） | block/blockaction | **既有票 HTTPDMAIN-F8-FORLOOP-0001（P1 待认领）** |
| **N. const 限定符** | 4 | my_get_token 2 / parseconfig 2 | `char *line` vs `const char *line`（DWARF const 限定在签名/实参 cast 链的传播渲染） | debugproto/typeprop | **新票 P3** |
| **O. \_DAT 槽尺寸** | 3 | myprogress | `_DAT_00107178 * V` + `Globals starting with '_' overlap` 警告:0x107178 为 4 字节 float 读,驱动非 string 引用条目统一 8 字节宽 → pushMismatchSymbol `_` 前缀 + mapGlobals inconsistentuse 双症状 | examples 驱动 | **新票 P3** |
| **P. do-nothing 警告** | 1 | _start | `/* WARNING: Do nothing block with infinite loop */` 缺发 | coreaction | **既有票 MSTRUCT-DONOTHING-WARN-0001** |
| **Q. 折行点** | 2 | main 1 / csu 1 | `if(…))\n{` vs `if(…)) {`;`(…)\n;` vs `(…);` | printc/prettyprint | **既有票 MIRATTR-F-WRAP-0001 同域** |
| **R. csu 掩码形** | 2 | csu | `((ulong)V & 7,…)` vs `(V,…)`——历史票 SUBFLOW-CSU-MASK-0001 的**反向**残留（golden 有掩码,Rugra 无） | subflow/规则 | 并入 J 车道观察项 |
| 残差（diff 配对混排） | ~8 | main 内 | union hunk 的 `_4_4_` 位移行等 | — | 随 D 收敛 |

合计 ≈267（§8 机器表 + 手工对侧合并;±2 行归属歧义已注明）。

## 3. 与在飞/已登记票交叉核对（勿重复归因清单）

| 在飞/已登记 | 与本表关系 |
|---|---|
| **wt/printcs（在飞,6 commit）** | `e8b6ec5e` CALLOTHER RPN 分派（httpd 面）/`de36abd3` F3-DOUBLECAST（httpd main L277 同型,main 未再出现）/`3f9a10e2` F-ARRCAST（httpd）/`83213b78` PKG-C printc facing 冻结 map/`6ec4e705` WHILEDO-LABEL（curl glob_word 悬空 goto,**已在该分支修复**=glob_word 现 0 的主因之一）/`4688115e` F-CODENAME docs。**并入后 curl canon 预期 −2**（任务预告口径）;PKG-C 对 D 族（union store 打印）可能同向改善,合并后须重测本表 |
| **VARMPOISON 车道在飞（MIRATTR-F-TYPE-FEED-0001,P0）** | C 族②（`(bool *)` 对向 cast,file2string/myprogress/my_get_line ~13 行）是 varmap 类型中毒环的 bool 变体——**归其收敛面,不重复立票**;C 族①③（typedef bool→char 元类型 + `(bool)` cast,~16 行）是 debugproto typedef 名解析,**独立立票**（修法不同:类型图入口,非中毒切断） |
| **HELPF-VARARGS-SAVECHAIN-0001（2026-09-01 w-varargs,历史"在途"）** | 车道从未交付（FLEET5 中断回收期）;29 行原样存续。**不新立票,标复活** |
| **HTTPDMAIN-F8-FORLOOP-0001（P1 待认领）** | M 族 4 行 + main for 混排行归其收敛面 |
| **HTTPDMAIN-F2-IMAGEBASE-0001（V4/V5 决策挂起）** | H 族 7 行=同根 curl 位点;`(undefined *)` cast 伴生随增量显示决策一并裁决 |
| **MIRATTR-F-DECL-0001 / F-WRAP-0001** | I/Q 族的既有票,curl 位点并入其验收面 |
| **MSTRUCT-DONOTHING-WARN-0001** | P 族 1 行,原票覆盖 |
| **STRLIT-ENVDAT-0001（DONE）** | &DAT 10 行族已收（−32）;**&UNK_00103c47 新位点**归 H/F2 裁决（代码地址 UNK 标签通道,非 string 通道） |
| **F7NAME（94e89d82 已并入 master）** | G 族=该机制在 curl 面的首个可见残差——机制在、参与集/覆盖序差 |

## 4. 逐族深归因（双侧行号+根因+修复规格）

### E. 静态作用域符号名（22 行,根因已钉死——本车道最有价值发现）

- **症状**:rugra `save =line;`（my_get_token,`curl_base.c:1128-1162` 13 站点）/`beenhere`（next_url 4 站点）vs golden `my_get_token::save`（`ghidra_curl_1204.c:1226-1250`）/`next_url::beenhere`。
- **符号源头（亲证）**:ELF symtab `save.5103`@0x17510 / `beenhere.3888`@0x17518（`readelf -s`）;DIE `parent_function=Some("my_get_token")`（debugproto.rs:75-78 注释即为本 witness 而写）。
- **根因链（源码级,无需再探）**:
  1. `build_worker_architecture` 的 legacy 种子层 `examples/curl_decompile.rs:3810-3856`:当 `arch.symboltab.is_none()` 时新建 DB 并用**未限定** `&global.name`（:3851）seed `save`;
  2. 前端通道的权威层 :5234-5251 `dwarf_display_names`（qualified）→ :5585-5598 `seed_global_locked`（qualified）对同一地址**再插一条**;
  3. `Funcdata::query_global_symbol_hit`（funcdata.rs:1531-1561）Channel 1 的 queryContainer/parent-scope pick 取**先插入**的裸名条目 → `high.set_name("save")`（funcdata.rs:1693,RUGRA_DUMP_FUNC 亲证 `vn#1800(h=save, INPUT:ram:17510)`）;
  4. printc 侧 `::` 处理已就绪（printc.rs:7475-7476 显式放行 precomposed 限定名）——纯上游喂名问题。
- **修复规格**:①最小修=:3851 改喂限定形（同 :5241-5243 的 `format!("{}::{}", parent, name)`）,两层同名幂等;②或 :5585 层先 `query_container` 查已存条目则改名/复用（镜像 GLOBWORD-C5 :3823-3844 的去重不变量,方向反过来）。修后 mirror 面 gate（bare-load 不喂 DWARF 层名,需核 :3810 块是否也要挂 `mirror_bare_load_enabled()` 门）。
- **写域**:`examples/curl_decompile.rs`（当前无车道持有 examples;驱动域 root 裁决惯例）。
- **验收**:`my_get_token::save`×13 + `next_url::beenhere`×4 与 golden 逐字节;curl canon 267→**245**;双跑 cmp 恒等;mirror 三面/canon httpd 不回退;bank 391/391。
- **预估收益**:−22。

### D. union store 仲裁（46 行,main 单函数最大池）

- **症状**:golden `glob.pattern[N].content = (anon_union_16_3_e2f18bb4_for_content)auVarN._8_16_;`（`ghidra_curl_1204.c:767-775` 8 站点 + `:781` `content._8_8_`）vs rugra `glob.pattern[N].content.Set = (union_5a7)auVarN._8_16_;`（`curl_base.c:685-693` 等）。
- **关键反例（钉死"非硬规则"）**:golden:746 与 rugra:664 同印 `glob.pattern[8].content.Set.elements = (char **)in_stack_…fd90;`——oracle 在该站点**确实下降到字段**,而初始化 8 站点**停在整成员**。双侧 `_0_4_/_4_4_` 同印,值通道同构。
- **根因方向**:store 地址的 union 字段解析深度逐站点仲裁——oracle 的 `resolveInFlow/findResolve`（type.cc 虚分派族）对 init 梯 8 站点判"不解析"（保持 union 成员+显式 cast）,对 pattern[8] 站点判"解析到 elements";Rugra 一律解析到 `.Set`。候选差位点:①`ScoreUnionFields` 评分/采纳门槛（unionresolve.rs:评分主体,审计判 aligned 但 store 目标侧未必覆盖）;②`RulePieceStructure`/`setUnionField` 的 attach 深度;③`TypeStruct::downChain` 对 union 容器的下降语义（type.cc:1084-1131——oracle 在 union 处停走交由 ScoreUnionFields,Rugra 直接取首字段）。
- **修复规格（先归因后修）**:oracle 单函数 drill（main@golden 环境,OPACTION_DEBUG/resolveInFlow 插桩,复用 sb-oracle trace 配方）钉 8+1 站点的逐站点解析决策 → 对照 Rugra 同站点评分流 → 修差位点。**注意 wt/printcs 在飞的 PKG-C（printc facing 冻结 map）合并后先重测**——若 D 族已被其收敛则本票撤。
- **写域**:`src/unionresolve.rs`+`src/type_system/datatype.rs`（downChain）+`src/coreaction.rs`（setUnionField 消费）——机制 C 白名单（union 消费谱系）。
- **验收**:main 8 站点 `content = (anon_union…)` 逐字节 + pattern[8] 站点保持 `.content.Set.elements`;curl 267→~221;canon httpd/bank/镜面不回退。
- **预估收益**:−46（若 PKG-C 未覆盖）。

### A. 原型驱动实参/存储 cast（45 行）

- **症状三形态**（golden 有 cast / Rugra 无,除 N 对向）:①实参 `fgets(buf,0x100,(FILE *)fp)`（my_get_line golden:520 侧）/`fclose((FILE *)stdin)`/`fileno((FILE *)outs.stream)`/`fwrite(…,(FILE *)::config.errors)`/`__xstat(1,…,(stat *)&fileinfo)`;②值侧 `outs.stream = (FILE *)stdout`/`(FILE *)fopen(...)`/`if((FILE *)outs.stream == …)`;③返回 `return(char *)__dest`。
- **根因方向（两层候选,需 fixture 定分）**:①castInput 对锁定原型 struct 指针参数的插入（typeop.cc:301 getInputCast/cast.cc:143-403 castStandard——SUB_PTR_STRUCT 特异性仲裁;驱动 6024-6029 的 dwarf_type_names 通道已在,值侧 return 生效而 input 侧不生效的差因待钉）;②**类型身份双对象**：golden 的 DWARF-FILE 与 libc 签名-FILE 在 analyzeHeadless 内是否同一 Datatype 对象（对象不同→同型 cast 也会插;Rugra GLIBCPROTO 统一工厂身份→不插）——与 MATCHURL-SETCASTS-337 的身份碎片史同谱系但方向相反（canon 需要"恰好的身份分离"）。
- **修复规格**:getparameter/my_get_line 单函数 fixture 双侧 setcasts 探针（CASTINS 计数+逐实参 token）,钉哪个 cast 决策点分歧（castStandard 返回 None vs Some）→ 修对应臂。**先做 fixture,证据未钉死前不动 src**。
- **写域**:`src/coreaction.rs`（setcasts）+`src/type_system/cast.rs`（castStandard）——机制 B/C 域。
- **预估收益**:−45（与 F 部分耦合,F 的局部定型翻转会改写其中 getparameter 段的形态）。

### B. helpf varargs（29 行,复活既有票）

- golden `ghidra_curl_1204.c:1030-1076`（13 声明+8+5 保存语句）vs rugra 全缺。原票归因仍有效（varargs param trials/保存链位置 condexe/fspec/va_list 渲染）。**行动=复活认领**（2026-09-01 后无车道持有;F7NAME 的 lookForFuncParamNames 已在 master,va_list/ap 渲染通道 helpf 两侧已同印 `va_list ap`——保存链只剩寄存器组与条件块）。
- **预估收益**:−29。

### C. bool 元类型（29 行,拆两半）

- **①typedef 名解析（~16 行）**:DWARF `typedef char bool`（`<938>` typedef→`<17f>` signed char,decl_file 19;全二进制 **0 个 DW_ATE_boolean** 亲证）+ `remotefile` 等 20+ 字段经该 typedef。oracle 的 DWARFDataTypeManager 按名解析 typedef `bool`→正典 bool（size 1 匹配）→ `== false`/`!= false`（main golden:695/712/738/1021 vs rugra:613/630/656/939）、`bool usedarg` 签名+`*usedarg == false`（gp golden:1611 vs rugra `*(bool *)usedarg`）、`(bool)(::config.remotefile ^ 1)`（gp golden:224 侧）。**修法**=debugproto typedef 层按名正典化（DWARFBASE 的 standard_base_alias 谱系扩展到 typedef 臂:名字在别名表且尺寸匹配→正典类型,含 metatype Bool）。**写域** `src/debugproto.rs`。
- **②( bool\* ) 对向 cast（~13 行)**:rugra `pbVar11 = (bool *)buffer`×2/`(bool *)(__ptr + V)`/`(bool *)line`×2/`(bool *)buf` vs golden 无 cast（golden 同名 pbVar 赋值直落）——castStandard 对同尺寸 pointee 指针族的免 cast 规则差 + varmap 中毒环（**归 VARMPOISON/F-TYPE-FEED 收敛面**）。
- **预估收益**:①−16（独立票）;②−13（VARMPOISON 面）。

### F. getparameter 局部类型仲裁（24 行）

- golden 的复用局部（`local_5b8`/V 梯,golden:754-781 区域）定型 `Configurable *`,各 FILE\* 用点带 cast（`(Configurable *)fopen`×3、`(Configurable *)0`×2、`(Configurable *)stdin`×2、`file2string((FILE *)V)`×2）;rugra 同组定型 `FILE *` → 全部对向。声明区 `FILE *V`↔`Configurable *V`×4 联动（已计入本族非 I 族）。
- **根因方向**:varmap 高类型仲裁（typeOrder 竞争/InferTypes 往返）——同一 COPY 链上 Configurable\* 用点（`(Configurable *)0` 比较、`&config` 赋值）与 FILE\* 用点的胜者翻转。**修复规格**:gp 单函数 IR fixture（merge 分组+逐 varnode temp type 双侧对照,复用 sb-addrslot/rangehint drill 配方）定位分岔轮 → 修仲裁。**写域** `src/varmap.rs`+`src/coreaction.rs`（InferTypes）。
- **预估收益**:−24（与 A 的 gp 段互斥,合并修复后两族合计去重计数 −24 而非 −33;保守报 −20）。

### G. \_\_stream 名推荐（12 行）

- golden `parseconfig` 局部 `FILE *__stream`（golden:1005 侧声明+:1040/:1048/:1057/:1102/:1105 使用 12 行）vs rugra `fp`。DWARF 局部真名=`file`（亲证,两侧都不用）;`__stream`=fclose libc 原型参数名推荐;`fp`=**my_get_line 的 DWARF 参数名**（亲证 DWARF）——Rugra 把内部函数 DWARF 参数名也纳入推荐并先赢。
- **根因方向**:lookForFuncParamNames 的被调参与集/覆盖序（oracle:分析期 Program 内已锁原型集;`numMergeClasses==1` 门 cc:2887）——先到先得还是后来居上的覆盖序,或内部 DWARF 原型是否入推荐源。**修复规格**:oracle drill（parseconfig 单函数,coreaction.cc:2853-2897 插桩录推荐序）→ 镜像序/参与集。
- **写域**:`src/coreaction.rs`（look_for_func_param_names/推荐存储）。
- **预估收益**:−12。

### H. image-base 显示（7 行,既有票 curl 位点）

- `uStack_150 = (undefined *)0x103af8/0x103b0e/0x103b23/…`×6+`&UNK_00103c47`×1（file2string canary 槽存代码地址）vs rugra base-0 `0x3af8`/`0x3c47`。归 HTTPDMAIN-F2-IMAGEBASE-0001 的 V4/V5 决策（(a) printc 显示增量 or (b) 驱动原生 rebase）;curl 位点并入其验收清单。`(undefined *)` cast 伴生随决策自决。
- **预估收益**:−7（决策后）。

### J. \_init/csu 原型恢复（11 行）+ R. csu 掩码（2 行）

- golden `int _init(EVP_PKEY_CTX *ctx)`（golden:3）+`_init(V)` 传参+`V=…;return V;`（7 行）与 `__libc_csu_init(EVP_PKEY_CTX*,…)`（golden:2653）+`(ulong)V & 7` 掩码形。EVP_PKEY_CTX 在二进制/DWARF/驱动全 0 出现（亲证）——analyzeHeadless 分析器（FID/签名库误配对 `_init` 桩的已知模式）知识。**归 headless 桥接数据域**（F7NAME 数据半同类）:驱动侧补台账或接受桥接层残差登记。P3。

### K. 入口 unaff 过参（4 行）

- rugra `_start` 3 参+`undefined8 unaff_retaddr;`+实参 `unaff_retaddr`（curl_base.c:4745 侧）vs golden 2 参+`V`（golden:1040）。entry thunk retaddr 的 heritage 提升进默认参数发现——MIRATTR-F-UNAFF-SUBFLOW-0001（def-less temp 传播）**不同机制位点**（此处是输入提升/参数发现域,fspec deriveInputMap irregular 过滤,golden 经 `_start` 命名原型通道排除）。P3,写域 fspec/heritage。

### L. 字段/数组下标形（5 行）

- `*(undefined4 *)&bar->field_LIT` vs `*(undefined4 *)((long)bar + LIT)`（progressbarinit:typed 指针字段解析,VARMAP-SPALIAS-RETYPE 环境绑定结论的 canon 侧残差,归 headless 类型回灌域）;`buffer._0_4_` vs `buffer[LIT]._0_4_`×2+`V = buffer + -V`（file2string:数组元素粒度渲染,RANGEHINT-ARRAYELEM 判例域 canon 位点）。P3。

### N. const 限定符（4 行）

- `char * my_get_token(char *line)` vs `const char *line`（rugra 签名+2 实参 cast `(const char *)0x0`）+parseconfig `(char *)LIT` vs `(const char *)LIT`。DWARF `const char*` 限定在 debugproto 原型/类型传播的渲染缺失。**写域** `src/debugproto.rs`。P3,−4。

### O. \_DAT 槽尺寸（3 行）

- myprogress:0x107178=4 字节 float（golden `DAT_00107178 * fVar10`,golden:1163）vs rugra `_DAT_00107178`+`Globals starting with '_' overlap` 警告（rugra:1069/1071 侧）。驱动 :5395-5415 对非 string 引用统一 8 字节宽 → 该 4 字节读触发 pushMismatchSymbol `_` 前缀+mapGlobals inconsistentuse。**修法**:驱动条目尺寸按引用宽度（.data 非 string 引用按首引用读宽,或该类 float 槽 4）——镜像 oracle analyzeHeadless 的真实 Data 尺寸。**写域** `examples/curl_decompile.rs`。P3,−3。**注意**:MIRATTR-F-WARN-CANON-0002（httpd 缺 13 警）是同域对向（DB 符号集形状）,修时双语料一起验收。

## 5. 新票登记（无票族;ID/优先级/写域/验收见 TODO_BOARD 同 commit 行）

| 新 ID | P | 行数收益 | 一句话 |
|---|---|---|---|
| `CURLCANON-DBSYM-DUP-RAWNAME-0001` | **P1-便宜** | −22 | worker legacy DWARF 种子层裸名与前端限定名层重复入 DB,先插者赢查询（curl_decompile.rs:3847 vs :5585） |
| `CURLCANON-UNIONSTORE-ARBITRATION-0001` | **P1** | −46 | glob init 8 站点 union store 停在整成员 vs Rugra 下降 .Set;pattern[8] 反例钉死为逐站点仲裁差 |
| `CURLCANON-PROTOCAST-INPUTS-0001` | **P1** | −45 | 锁定原型 FILE*/stat* 实参+值侧 cast 插入决策（castStandard/castInput）;须先 fixture 钉决策点 |
| `CURLCANON-BOOL-TYPEDEF-0001` | P2 | −16 | DWARF `typedef char bool` 按名正典化为 bool 元类型（DWARFBASE 别名表扩展到 typedef 臂） |
| `CURLCANON-GP-LOCALTYPE-0001` | P2 | −20~24 | getparameter 复用局部 Configurable* vs FILE* 定型仲裁翻转 |
| `CURLCANON-NAMEREC-PRECEDENCE-0001` | P2 | −12 | 多被调名推荐覆盖序/参与集（__stream vs fp） |
| `CURLCANON-INITPROTO-FID-0001` | P3 | −11 | _init/csu 的 EVP_PKEY_CTX 分析器知识（桥接数据域;含 csu 掩码形 2 行观察项） |
| `CURLCANON-ENTRY-UNAFF-0001` | P3 | −4 | _start retaddr 提升为第 3 参 |
| `CURLCANON-CONSTQUAL-0001` | P3 | −4 | const 限定符渲染缺失 |
| `CURLCANON-DATSLOT-SIZE-0001` | P3 | −3 | .data DAT 条目 8 字节默认宽 vs 4 字节 float 读（\_DAT\_ 前缀+overlap 警告双症状） |
| `CURLCANON-FIELDARR-CANON-0001` | P3 | −5 | bar->field / buffer[0]._0_4_ canon 位点（typed 回灌/数组粒度域,挂既有判例） |
| 复活 `HELPF-VARARGS-SAVECHAIN-0001` | P1 | −29 | 2026-09-01 死车道复活认领（29 行原样存续,va_list 渲染已就绪只剩寄存器组/条件块） |

## 6. 修复顺序建议（依赖+解封）

```
1. CURLCANON-DBSYM-DUP-RAWNAME-0001 (驱动,一行级,−22) —— 立即;root 裁决 examples 写权
2. CURLCANON-BOOL-TYPEDEF-0001 (debugproto 空闲?,−16) —— 与 DWARFBASE 同域经验
3. HELPF-VARARGS 复活 (condexe/fspec,−29) —— 独立 write-set
4. CURLCANON-UNIONSTORE-ARBITRATION (−46) —— 先等 wt/printcs 合并重测(PKG-C 可能改面);
   fixture=oracle resolveInFlow drill
5. CURLCANON-PROTOCAST-INPUTS (−45) + CURLCANON-GP-LOCALTYPE (−24) —— 互耦合(gp 段去重),
   先 fixture 后修;setcasts/varmap 写域解封后
6. CURLCANON-NAMEREC-PRECEDENCE (−12) —— coreaction 域解封后
7. H(imagebase,F2 决策) / I(F-DECL) / M(F8) / P(DONOTHING) / Q(F-WRAP) —— 跟既有票
8. P3 小票(J/K/L/N/O) —— 择机
```

理论收敛上限:22+46+45+29+16+24+12+7+8+4+1+2+11+4+4+3+5 ≈ **243/267**（余 ~24=H 待决策/I-F 族声明面投影重叠双计与 diff 混排行,随各票自然消化）。

## 7. 只读合规声明

本车道零 repo `src/` 改动、零 examples 改动;全部探针/脚本/输出在 `/dev/shm/rugra-tests/curlattr/`（full_diffs.py/classify.py/15 个 .diff/curl_base{,2}.c/cmp_full.txt）。RUGRA_DUMP_FUNC 只读插桩复用（无 src 写）。oracle 源码行号引用（printc.cc:7475 对应物/type.cc downChain/coreaction.cc:2853-2897 等）为函数级定位,深读留给各修复车道（机制 E hook 回执要求届时履行）。

## 8. 附:机器分族表（classify.py v3 输出,raw ±行）

```
F01-PROTOCAST 33 | F05-UNIONSTORE 32(+14 混排) | F02-VARARGS 28(+1) | F04-BOOLTYPE 22(+7)
F06-STATICSCOPE 22 | F03-LOCALTYPE 17(+3) | F07-NAMEREC 12 | F08-USTACK→H 12 | F10-PROTOREC 10(+1)
F09-DECL 8 | F12-ENTRYUNAFF 5 | F17-FIELDARR 4 | F13-FORSPLIT 3(+1) | F11-DATPREFIX 3
F14-CONSTQUAL 2(+2) | F19-WRAP 3 | F20-CSUMASK 1(+1) | F18-DONOTHING 1 | F21-TYPEOPEXPR 1
TOTAL 267(含对侧合并注记)
```

## 9. 附:复现脚本全文（自包含,/dev/shm 清理后可直接重建）

`full_diffs.py`（全函数无截断骨架 diff,复用 compare_ghidra.py 归一化）:

```python
import sys, difflib, os
sys.path.insert(0, '<repo>/tools')
import compare_ghidra as cg
rugra_c, ghidra_c, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(outdir, exist_ok=True)
rfuncs = cg.parse_functions(open(rugra_c).read())
gfuncs = cg.parse_functions(open(ghidra_c).read())
pairs = cg.match_functions(rfuncs, gfuncs)
for addr, rname, rbody, gname, gbody in sorted(pairs):
    d = list(difflib.unified_diff(cg.normalize_skeleton(gbody), cg.normalize_skeleton(rbody),
                                  fromfile='ghidra/'+gname, tofile='rugra/'+rname, lineterm='', n=2))
    n = sum(1 for l in d if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))
    if n:
        open(os.path.join(outdir, gname.replace('/', '_') + '.diff'), 'w').write('\n'.join(d) + '\n')
        print(f"{gname}: {n} raw +/- lines")
```

`classify.py`（逐行分族;正则序敏感,以本文 §2 手工合并表为权威口径）:见 git 历史 `/dev/shm/rugra-tests/curlattr/classify.py` v3（关键序:VARARGS→UNIONSTORE→PROTOCAST→LOCALTYPE→BOOLTYPE→STATICSCOPE→NAMEREC→PROTOREC→ENTRYUNAFF→DONOTHING→USTACK→DATPREFIX→UNKADDR→CONSTQUAL→FORSPLIT→FIELDARR→CSUMASK→WRAP→DECL→TYPEOPEXPR;±对侧行手工并回本族）。
