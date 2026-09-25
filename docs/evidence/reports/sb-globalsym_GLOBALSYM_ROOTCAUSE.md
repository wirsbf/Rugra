# 全局结构体符号映射根因调查(Lane Y)

- 日期: 2026-09-22 | 工作目录 /home/ls/Rugra(只读,产物全部在本目录)
- 输入: `/dev/shm/rugra-tests/sb-baseline/curl_new.c`(Rugra 基线) vs `tests/golden/ghidra_curl_1204.c`(oracle 12.0.4, e40ed130)
- 复核函数: `main`、`getparameter.constprop.0`(Rugra)↔ `getparameter`(oracle,Ghidra 无 constprop 克隆)
- 运行观测: `cargo build --profile fast-release --example curl_decompile` + `RUGRA_DUMP_FUNC` 全 IR dump + `RUGRA_RULE_STATS`;独立探针二进制(本目录 `probe/`,依赖 rugra lib,零 repo 改动)
- 相关分诊: `/dev/shm/rugra-tests/sb-triage/TRIAGE_MAIN_GETPARAM.md` C4/C4'

---

## 0. 丢失层判定(一句话)

**符号导入层与类型层的数据全部就位(`config`→`Configurable`(304B,41 字段)已安装且 IR 里 high 已挂 `config` 符号);丢失发生在 ① 类型分派层(`Datatype::get_sub_type` 虚分派缺 Spacebase 覆写 → `RulePtrsubUndo` 把 spacebase-PTRSUB 撤成 INT_ADD → gp 的 16 行 `__spacebase_1_0` 形态)+ ② 打印层(`get_varnode_display_name_inner` 的 Priority-0 `symbol_table` 代理查询先于符号 high 解析,叠加 driver 对符号 span 内部逐字节播种 DAT_ 名 → main/gp 的 165 行 `DAT_xxx` 形态)。**

两个家族是**两个独立缺陷**,都发生在消费端(类型门禁/打印),不是 database/importer 缺符号。

---

## 1. 现象固化:双侧全局访问形态对照

### 1.1 符号存在性(ELF/DWARF 事实)

```
$ readelf -sW examples/curl
  49: 0000000000017520   304 OBJECT  GLOBAL DEFAULT  26 config        # .bss, DWARF: DW_TAG_variable CU 级, DW_OP_addr 17520
  87: 0000000000017660     8 OBJECT  GLOBAL DEFAULT  26 glob_expand
  79: 0000000000017680  4096 OBJECT  GLOBAL DEFAULT  26 glob_buffer
```
ELF 64-bit PIE, not stripped, with debug_info。镜像基址 0x100000(Ghidra AnalyzeHeadless 约定),故 `config` → 0x117520。

### 1.2 Rugra 侧 DAT 引用 100% 是 config 字段(按数据对象聚类)

对 main/gp 的全部 `DAT_[0-9a-f]+` 引用按 `addr − 0x117520` 折算字段(字段表来自 DWARF `Configurable`,探针实测 41 字段与 oracle `::config.<name>` 完全一致):

| 函数 | DAT 总数 | 落在 config span [0x17520,0x17640) | 其他对象 | oracle 对侧 |
|---|---|---|---|---|
| main | 105(35 个不同地址) | **105(100%)** | 0 | `::config.<field>` 113 次/36 字段 |
| gp | 60(16 个不同地址) | **60(100%)** | 0 | `::config.<field>` 116 次/38 字段 |

热度完全同构(main: `.conf`×20↔oracle×21、`.outfile`×13↔×20、`.infile`×7、`.errors`×7↔×8;gp: `.conf`×22↔×28、`.httpreq`×7↔×10)。**URLGlob/glob_buffer/glob_expand 不出现在 DAT 族**(它们走 C11 大对象拷贝族,另案)。

main 对照样例(rugra `main_dump.c:251` ↔ oracle `main_oracle.c:138`):
```
+ if ((DAT_00117550 == (char *)0x0) && (DAT_00117560 == '\0')) {     # 0x117550=+0x30 .outfile, 0x117560=+0x40 .remotefile
- if ((::config.outfile == (char *)0x0) && (::config.remotefile == false)) {
```

### 1.3 gp 的 `__spacebase_1_0` 家族(16 行)

15 行 `+ 0x17520`(config 基址)+ 1 行 `+ 0x17020`(.data PTR_DAT_00117020 槽),全部是**地址取用(&global)**而非读值:

```
+ GetStr(&((Configurable *)((int *)(__spacebase_1_0 *)0x0 + 0x17520))->proxy,nextarg);   # rugra gp:221
- GetStr(&::config.proxy,(char *)local_5b8);                                             # oracle gp:172
+ uVar27 = (undefined **)((int *)(__spacebase_1_0 *)0x0 + 0x17020);                      # rugra gp:53
```
注意外层 `->proxy` 字段打印**是好的**(类型层 Configurable 已生效),坏的是内层 `spacebase+0x17520` 没折叠成 `::config`。

---

## 2. 分层定位:三层证据

### (a) 导入/符号层 —— ✅ 就位,无缺口

- **运行时证据 1**(`run_main.err`):`[PREPASS] Program-DB global symbol layer: 164 entries` + `[PREPASS] main program-DB symbol graph: 59999 .rodata entries (131 string-typed) + 159 global symbols (5 DWARF-typed)`。
- **运行时证据 2**(独立探针 `probe/`,复刻 driver 的 `program_db` DWARF 播种):
  ```
  parsed globals: 5
    0x17520 config size=304 type="Configurable"     ← 名字+大小+类型全对
  STRUCT Configurable nfields=41: +0x30 outfile, +0x88 proxy, +0x98 conf, ... (与 oracle 字段名逐一吻合)
  query_container(0x17520) -> Some(("config", 0x17520, 304))
  query_container(0x17550) -> Some(("config", 0x17520, 304))   ← mid-symbol 命中 config(span 覆盖)
  query_container(0x175a8) -> Some(("config", 0x17520, 304))
  ```
  (ELF 里共 17 个静态 DW_TAG_variable;driver 只吃 DW_OP_addr 直址的 5 个,恰好覆盖 config/glob_buffer/glob_expand/beenhere/save —— 与 oracle golden 的具名全局集合一致,不缺。)
- **驱动安装路径**:`examples/curl_decompile.rs:2405-2418`(worker program_db,DWARF 层 typelocked:`DebugGlobalDatabase::seed_global_locked`)与 `:1968-2031`(arch.symboltab 补种)。链路完整。

### (b) 类型层 —— ✅ IR 已挂符号;❌ 一个**虚分派缺口**只影响"地址取用"家族

- **运行时证据 3**(`RUGRA_DUMP_FUNC=main` 全 IR dump,`main_dump.err`):
  ```
  op CPUI_COPY out vn#55679(h=config:unique) = (vn#41719(h=config, INPUT:ram:17550, t=Pointer/))
                ^^^^^^^^^ high 名字已是 config —— RuleLoadVarnode + linkSymbol 全部工作了
  ```
  即:`LOAD(ram,const)` 已被 `RuleLoadVarnode` 折成直址 ram varnode,`Funcdata::link_symbol` 的 parent-scope 查询(MAINDIFF-UNIQLEAK-0001 修复点)已把 `config` SymbolEntry(offset 0x30)挂上。**IR 层不丢符号。**
- **运行时证据 4**(gp IR dump,`gp_dump.err`,GetStr@0x4669):
  ```
  COPY    rdi ← const:175a8                    ← 原始 lift,正确(lea rip-rel 已折直址)
  CAST    u(int8)  ← const:0 (Pointer/ 空名)    ← spacebaseConstant 的 SB0
  INT_ADD u2 = u + const:17520                 ← ★ 基址 PTRSUB 被撤成 INT_ADD
  CAST    p(Pointer) ← u2                      ← (Configurable *)
  PTRSUB  out = p + const:0x88                 ← ->proxy 正常
  ```
- **类型层缺口**(探针二分定位):
  - `TypeSpacebase::get_sub_type`(src/type_system/datatype.rs:4069,对应 type.cc:2947)**本身工作正常**:探针直调返回 `Some("Configurable")`。
  - 但通用虚分派 `Datatype::get_sub_type`(datatype.rs:838)把 `Spacebase(_)` 归入 `=> (None, off)` 基类行为;`get_sub_type_arc`(datatype.rs:880)注释自认 "The Spacebase arm … **remains a documented whole-dispatch mismatch**"。
  - 消费方分裂:`pointer_is_ptrsub_matching`(datatype.rs:2186,Spacebase 臂调通用分派 → 恒 false)vs `RulePtrsubUndo::is_ptrsub_matching`(ruleaction.rs:15044 已显式 dispatch 到覆写)。运行时最终 IR 里 SB0 指针的 pointee 名为空(`t=Pointer/`,非 `__spacebase_1_0 *`),说明门禁读到的 basevn 类型是传播期"spacebase rewrap 成 unknown\*"(typeop.rs:755-790/2595-2630,COPY/INDIRECT 传播的忠实移植)或 typelock 被覆写的产物 → 匹配失败 → 撤销。**结论:即便 RulePtrsubUndo 的分派修了,还需保证门禁读到 SB0 的 typelocked `__spacebase_1_0 *`(oracle 中 constructConstSpacebase 的 updateType(ptr,true,true) 使传播无法覆盖)。**

### (c) 打印层 —— ❌ DAT 家族的直接产地(双层叠加)

- **打印层缺口 A(优先级倒置)**:`src/printc.rs:5752-5762` `get_varnode_display_name_inner`:
  ```rust
  if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
      if let Some(sym_name) = self.symbol_table.get(&addr) { return sym_name.clone(); }  // Priority 0
  ```
  RPN 生产路径的叶子 atom(`make_atom_for_vn` printc.rs:1584→1628)先走这里;**在** `vn.high`(已挂 `config` 符号,printc.rs:5770-5812 `high.symbol.is_some() → return name`)之前就 return 了。Ghidra 的 `pushVnExplicit→pushSymbolDetail`(printlanguage.cc:218-262)**不存在任何按地址查名字代理**:sym 非空 → `symboloff` → `pushPartialSymbol`。
- **打印层缺口 B(缺 partial-symbol 叶子形态)**:即使去掉代理,叶子路径只会吐 high 名 `config`,而 oracle 对 mid-symbol 直址 varnode 走 `PrintC::pushSymbolLocation`(printc.cc:1875-1890:entry size 304 ≠ vn size 8 → `pushPartialSymbol(sym, off=0x30, …)`)→ 字段走名 `::config.outfile`。Rugra 的 `push_partial_symbol`(printc.rs:14501)存在但只接在 PTRSUB-spacebase 臂(printc.rs:2181/11455),**没接叶子路径**。
- **Driver 侧放大器(span 盲播)**:`examples/curl_decompile.rs:3750-3769` 对 `.data/.bss` 每个字节 `if !symbol_table.contains_key(&addr) { insert(synthetic_dat_name(addr)) }` —— 只查**起始地址**,不查 span。于是 `config`(0x17520,304B)内部 0x17521..0x1763f 全部得到 `DAT_00117521..DAT_0011763f` 代理名(query-channel Database 侧对 strings 做过 STRCONST-SPANNONOVERLAP 修复,**symbol_table 代理侧没做同样的处理**)。oracle 前端 Program DB 的 Data 严格不重叠,具名符号内部不会出现 DAT 标签。

---

## 3. Ghidra 对照(oracle 侧完整链路,引文级)

**值读形态 `::config.outfile`**(main/gp 的 165 行 DAT 族):
1. `RuleLoadVarnode`(ruleaction.cc:4270-4305):`LOAD(ram, const)` / `LOAD(ram, spacebase+const)` → `COPY(ram:addr)`,全局内存读变直址 varnode(ruleaction.cc:4293 `newVarnode(size, baseoff, offoff)`)。
2. varmap `Funcdata::linkSymbol`(varmap.cc:1169,Rugra 对应 funcdata.rs:1442+ 已移植):`Scope::queryProperties` parent-walk(database.cc:943-975 stackContainer)命中全局 `config` SymbolEntry → `vn->setSymbolEntry(entry)` + `high->setSymbol(vn)`。
3. `PrintLanguage::pushVnExplicit → pushSymbolDetail`(printlanguage.cc:218-262):`symboloff`(0x30)≠−1 且 `symboloff+size ≤ sym->getType()->getSize()` → `pushPartialSymbol(sym, symboloff, size, …)`。
4. `PrintC::pushPartialSymbol`(printc.cc:1932-1990):沿 `sym->getType()`(DWARF `Configurable`)下钻字段 → `globalstruct.arrayfield[0]` 形态;`pushSymbolScope`(printc.cc:202-226)在 `namespc_strategy` 下吐 global scope 前缀 `::`。

**地址取用形态 `&::config.proxy`**(gp 的 16 行 spacebase 族):
1. `ActionConstantPtr`(coreaction.cc:1167-1214):常量指针经 `isPointer`(coreaction.cc:1070-1165,`queryContainer(rampoint,1,Address())`)命中符号 → `data.spacebaseConstant(op,slot,entry,…)`。
2. `Funcdata::spacebaseConstant`(funcdata.cc:360-462):重写为 `PTRSUB(const0-SB, entry基址偏移)` + 可选 `INT_ADD(extra)`;const0 typelock 为 `TypeSpacebase*`(funcdata.cc:405-409 `updateType(sb_type,true,true)`)。
3. **存活门禁** `RulePtrsubUndo`(ruleaction.cc:7128-7141):`basevn->getTypeReadFacing(op)->isPtrsubMatching(val,extra,multiplier)`;`TypePointer::isPtrsubMatching`(type.cc:1123-1141)SPACEBASE 臂做**虚分派** `ptrto->getSubType(newoff)` → `TypeSpacebase::getSubType`(type.cc:2947-2969:`getMap()` 动态取 `glb->symboltab->getGlobalScope()`,`queryContainer` 查 `config`)→ 命中 → PTRSUB **保留**。
4. `PrintC::opPtrsub` TYPE_SPACEBASE 臂(printc.cc:1059-1101):`op->getIn(1)->getHigh()->getSymbol()` → `pushSymbol`/`pushPartialSymbol` → `&::config` / `::config`;外层 flex PTRSUB 吃掉 `&` → `.proxy`(printc.cc:992-1006)。

**Rugra 对应缺口**:第 3 步(虚分派 Spacebase 臂 + SB0 typelock 存活)与第 4 步的 in1-high 符号附着(`ActionNameVars` namerec 为已登记 no-op,FUNCDATA-LINKSYMBOL 残差;printc.rs:2394/11388 已用 container-query 代理兜底,但 op 已不是 PTRSUB 时代理永不触发)。

---

## 4. 与已知登记项的关系 + 登记建议

| 现有 ID | 内容 | 是否本族 |
|---|---|---|
| `PTRSUB-TYPED-DECL-RESIDUAL-0001` | printc.cc:143-166 buildTypeStack 匿名 PTR/ARRAY/CODE **声明 type-token 缺失**(`pCVar29;` 裸声明) | **否**。那是声明形态;本族是**引用形态**(DAT_xxx/spacebase 算术)。IR 已挂符号这一点与该 ID 的"无类型 concrete-pointer declaration"前提相反 |
| `TYPEOP-PTRSUB-FIELDCAST-0001` | PTRSUB localtype INT 保持 + castOutput token 消费 | **部分相邻**:gp 外层 `->proxy` 字段打印成功正是这条链路的成果;`(int *)` cast churn 与本族 INT_ADD 形态有交集,但 spacebase-PTRSUB 被撤销的根因(get_sub_type 虚分派)不在其登记范围 |
| `PTRSUB-SWITCH-CAST-RESIDUAL-0001` | glob_set switch 表达式 cast churn | 否 |

**建议新开 2 个 ID**(root 集成阶段登记;本 lane 只读):

1. **`TYPE-SPACEBASE-SUBTYPE-DISPATCH-0001`**(P0,类型层,修复面窄)
   - write-set: `src/type_system/datatype.rs`(838 `get_sub_type` / 880 `get_sub_type_arc` / 2186 `pointer_is_ptrsub_matching` 的 Spacebase 臂全部路由到 4069 覆写)、`docs/api/type_system/datatype.md`、fixture `tests/oracle/type_spacebase_subtype_1204.*`
   - 验收: 探针级(本目录 `probe/` 三连:直调/通用分派/is_ptrsub_matching 一致)+ gp `__spacebase_1_0` 16 行清零(`&::config.<field>` 形态)+ 既有 ptrsub_output_token fixture 不回归。
   - 附带核查点: SB0 const 的 typelocked `__spacebase_1_0 *` 是否被传播覆写(typeop rewrap),门禁读 type 的 read-facing 路径。
2. **`PRINTC-GLOBALSYM-LEAF-PRIORITY-0001`**(P0,打印层 + driver,消解 main/gp 全部 165 行 DAT)
   - write-set: `src/printc.rs`(5752 Priority-0 代理移到符号解析之后/删除 Ram|Const 代理分支;`make_atom_for_vn`/`get_varnode_display_name_inner` 接 `push_partial_symbol` 叶子形态,对齐 printlanguage.cc:238-262 + printc.cc:1875-1890)、`examples/curl_decompile.rs:3750-3769`(symbol_table 逐字节播种改为 span 感知,复用 DB 侧 STRCONST-SPANNONOVERLAP 的 skip/clip 语义)、`docs/api/printc.md`
   - 验收: main+gp `DAT_00117[5-6]xx` 清零、`::config.<field>` 计数对齐 oracle(113/116)、defects/numbering=0、gcc 审计不劣化、`&DAT_0010xxxx`(.rodata 无符号区,witness `&DAT_00107180`)形态**不变**(那是合法 oracle 形态,别误伤)。

两个 ID 可并行(write-set 无交集);先修 2 收益大(165 行),修 1 再收 16 行。

---

## 5. 复现/工件清单(本目录)

| 文件 | 内容 |
|---|---|
| `main_rugra.c` / `main_oracle.c` / `gp_rugra.c` / `gp_oracle.c` | 函数体提取 |
| `main_dump.err` / `gp_dump.err` | `RUGRA_DUMP_FUNC` 全 IR dump(17k+ op,含 space/type/high 三态) |
| `main_dump.c` / `gp_dump.c` | dump 模式下的 C 输出(= 基线形态) |
| `run_main.log` / `run_main.err` | `RUGRA_RULE_STATS=1` 运行日志([PREPASS] 符号层计数在 err) |
| `probe/` | 独立 cargo 探针(DebugGlobalDatabase 解析、DB 播种复刻、scope snapshot / get_sub_type / is_ptrsub_matching 三级测试) |

关键命令:
```bash
RUGRA_DUMP_FUNC=main ./target/fast-release/examples/curl_decompile --rugra-selected-function main
RUGRA_DUMP_FUNC=getparameter.constprop.0 ./target/fast-release/examples/curl_decompile --rugra-selected-function getparameter.constprop.0
```
