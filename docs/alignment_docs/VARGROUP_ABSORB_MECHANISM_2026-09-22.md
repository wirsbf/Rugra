# VARGROUP-ABSORB-0001 机制图与车道现场(2026-09-22, CT lane)

> oracle = Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b。
> 双侧证据:curl 二进制 sha256=8af50bca…(同 golden 指纹),main=0x25a0,match_url=0x5220,
> match_url 调用点=0x30d6。本文是 lane 现场记录 + 已证实机制图 + 精确分歧点。

## 1. 已证实的 oracle 机制链(main 的 `glob.pattern[i].xxx` 吸收)

双侧实证(非推断):

1. **DWARF**:match_url 形参2 = `glob`,类型 URLGlob(304B:
   literal[10]@0, pattern[9]@80, size@296),位置 `DW_OP_fbreg:0` =
   callee stack:0x0 = 调用方 main 帧内 -0x388..-0x250 的 304B 传出区。
   main 自身 DWARF **无** `glob` 局部(仅 urls@-0x220/urlnum@-0x224 等)——
   golden 的 `URLGlob glob` 符号完全由反编译器从调用点锁原型生成。
2. **ActionFuncLink::funcLinkInput**(coreaction.cc:1474-1513):locked 调用点
   stack 形参 → `opStackLoad` 304B LOAD + spacebasePlaceholder。
3. **SplitDatatype::splitCopy/splitLoad**(subflow.cc:2296-2800):把 304B 载入
   拆为字段件(SUBPIECE 输出落在 **栈地址** fc78+80 等) + PIECE 重组梯。
4. **RulePieceStructure**(ruleaction.cc:7607-7700):树根有结构化类型(URLGlob)
   → 叶子重定位到结构字段地址,插 COPY → 打印成字段 store。
5. **Merge::groupPartials/groupPartialRoot**(merge.cc:967/1374):CONCAT 树建
   VariableGroup;**Funcdata::linkProtoPartial**(funcdata_varnode.cc:1132-1149)+
   `establishGroupSymbolOffset`(variable.cc:610)让件共享根符号。
6. **printc opSubpiece 特殊打印**(printc.cc:843-878,doesSpecialPrinting+
   isPieceStructured)→ `pushPartialSymbol` 字段路径。
7. **命名 `glob`**:ActionNameVars::lookForFuncParamNames::makeRec
   (coreaction.cc:2815-2897),要求 param **isNameLocked**(DWARF 提供)且
   high 非 addr-tied。

## 2. oracle 控制台单函数复现(决定性实验)

`/tmp/rugra-ghidra-oracle-dbmap`…decomp_opt(从锁定源码重建,-D__TERMINAL__,
bfd=/tmp/rugra-ghidra-bfd-2.38) + 脚本手工注入类型与调用点原型
(`parse line` 注意:int4 拼写/typedef 名引用/tag 引用不可用/声明需尾分号;
地址写 0x30d6):

```text
override prototype 0x30d6 char *match_url(char *filename, URLGlob glob) ;
```

输出(work/oracle_main.c)复现 golden 形态:

```c
UVar3.pattern[8].content.Set.elements = (char **)in_stack_fffffffffffffd90;
UVar3.literal[0] = (char *)in_stack_fffffffffffffc78._0_8_;
UVar3.pattern[0].type = SUB248(in_stack_fffffffffffffc78._80_24_,0);
UVar3.pattern[0].content = (ContentUnion)SUB2416(in_stack_fffffffffffffc78._80_24_,8);
...
pcRam… = match_url(pcRam…,UVar3);
```

与 golden 仅差:①符号名 UVar3 vs glob(override 的 param 无 NAME_LOCKED 位,
makeRec 拒绝——真实 DWARF 锁名);②缺 `._4_4_` padding store(手工布局差)。
**结论:仅需调用点锁原型即可产生字段吸收形态;命名与 padding 是二阶差。**
脚本与输出存 /dev/shm/rugra-tests/sb-vargroup/work/oracle_main.{cmd,c}
(内存盘,重启即丢;脚本内容已录于本文件可重建)。

## 3. Rugra 现状(probe 实测,commit 1cd9f682)

- master 合并(CQ splitCopy)后 group_partials **已工作**:
  `with_piece=452`,45 件×size280 组=main 的 glob 梯;此前 probe3 的
  with_piece=0 是 **合并前旧代码** 的过期诊断。
- 304B 栈读存在且被 directify:`30d6:c33 COPY out=u:100000a1:304
  in=n:stack:fffffffffffffc78:304`。
- match_url DWARF 原型解析正确:param1 glob URLGlob 304
  struct[literal@0,pattern@80,size@296]。
- RulePieceStructure/determine_datatype 存在;304 根
  `structured=Some("URLGlob")` 判定通过。
- **最终 IR**:调用实参 = `u:10000a06:304`(join/寄存器域 PIECE 梯),
  而 oracle 是栈域(件读+字段 store+整读)。→ C 输出 CONCAT 梯。

## 4. 精确分歧点(CW 车道修正,2026-09-22 双侧 drill/raw 实证)

> **勘误**:本节原推断"rugra 的 heritage 把影写在 280B 粒度合并成 MULTIEQUAL、oracle 保持
> 输入影子域"——**双侧实证推翻**:oracle 的最终 raw(oracle 控制台 `print raw`,
> work/raw_main.out)同样有 280B 影写链:每个 spacebase store 一个全范围 INDIRECT
> (heritage.cc:1538-1559 guardStores 无条件按 range 建 INDIRECT),MULTIEQUAL@0x2806 合并
> (`s0xfc78:118(0x30d0:357c) = ...@0x2806:3587 ? ...@0x30d0:356e`),调用实参链的值最终
> 打印为输入影子 `in_stack_fc78[280]` 是**打印层**行为(high 符号 + partial 记法),
> 不是"读保持输入"。heritage 影写合并两侧一致。

真正的分歧链(drill @BEGIN 4961-4963 + oracle raw 逐 op 对照):

1. **RulePieceStructure 丢空间**(ruleaction.cc:7644):`baseAddr = outvn->getAddr() - baseOffset`
   的减法在 Ghidra 保持根的(唯一)空间;Rugra 用无空间 `Address::new(offset)` +
   `new_varnode_out` 的 Register 钉死 → concat 梯叶子/中间件落 Register 空间唯一式偏移
   (r0x10000b2e 等;oracle 等价物 u0x10000b4f = 根偏移+字段偏移,偏移一致仅空间错)。
   → **已修(PIECESTRUCT-SPACE-0001,commit a77d6c02)**:root_space 贯穿 + 双元组地址比较
   + new_varnode_out_full/new_varnode_in_space。
2. **栈 varnode 缺 addrtied → RuleSubRight 化 SUBPIECE 为 INT_RIGHT**(ruleaction.cc:7265-7268
   `outvn->isAddrTied() && a->isAddrTied() && overlap==c → return 0`):oracle 的
   `Funcdata::newVarnodeOut/setVarnodeProperties` 经 localmap->queryProperties 给在域栈
   varnode 折叠 mapped|addrtied(funcdata_varnode.cc:30-35 → database.cc:1268-1277,无符号
   条目也如此);Rugra 的 set_varnode_properties 只走 Ram/全局通道,栈 varnode 从不
   addrtied → splitCopy 建出的 45 个栈地址 SUBPIECE(42a0-42b2,件本身与 oracle 完全
   同形!)被 subright 拆成 280B 移位梯 → 42 处 CONCAT 中间态的直接诱因。
   → **已修(v2,commit bc45a768)**:place_multiequals 的 MULTIEQUAL 输出改走
   new_varnode_out_full 完整尾(=Ghidra cc:2634 原调用形态,local 腿折叠 addrtied)。
   v1(a77d6c02)的 set_varnode_properties 全局 fold+spacebase 挂载按 config 域 A/B 证据
   撤回(glob_set/glob_range 合并回退+__spacebase_1_* 合成名泄漏);v2 后 glob_set/
   glob_range/glob_url 逐函数 IDENTICAL,getparameter 向 golden 靠拢(golden 有
   local_5a8/local_5b8 栈名)。守卫用双侧 tied 即跳(保守版,等价覆盖 overlap==c)。
3. **typing 链断裂(未修,下一环)**:oracle 的 `ActionInferTypes::propagateSpacebaseRef`
   (coreaction.cc:5258-5306,apply 尾 5407-5410)依赖 SP 输入寄存器带 TypeSpacebase 指针类型
   (funcdata.cc:263-264)且存在"锁定调用点参数 → LOAD 输出临时类型 URLGlob → LOAD 反向
   传播(TypeOpLoad cc:493-496)→ ADD(RSP,8) 得 URLGlob* → INT_ADD/INT_SUB 链回传到 SP
   直接后代"——Ghidra 侧**调用点的 opStackLoad LOAD 活到最后**(最终 raw 仍有
   `0x30d6:c5b INT_ADD RSP+8` + `c5c LOAD 304`)。Rugra 侧该 LOAD 在 mainloop 早段已被
   directify 成 COPY(stack:fc78:304) 再接 concat 梯,infertypes 时 URLGlob 落在
   PIECE 根上而非指针上 → SPACEREF 接收端已移植(a77d6c02,INFERTYPES-SPACEREF-0001;SP 类型挂载撤回待 LOAD 链接通后一并启用)但派发的
   40 个 ADD 输出临时类型是 Int → ME/输入影子无 TypePartialStruct → subright 的
   pieceStructured 分支(cc:7256)与 printc opSubpiece/cc:843 特殊打印不触发。
   **下一环 = 调用点 LOAD 的存活语义(RuleLoadInput/directify 侧差异)**。

   > **勘误(2026-09-23,HERITAGE-LOADCLAIM-0001 lane,oracle gdb 逐步轨迹)**:本节
   > "Ghidra 侧 opStackLoad LOAD 活到最后/最终 raw 仍有 0x30d6:c5b+c5c LOAD"的表述
   > **不成立**——那是 CW 当时观测到的某个中间窗口,非终态路径。oracle 真实序列(gdb
   > 断点+backtrace 实证,decomp_opt 锁定源码):①mainloop 迭代1 oppool2
   > **RuleLoadVarnode(ruleaction.cc:4278)把 LOAD directify 成 COPY(s@fc78:130)**
   > ——与 Rugra 相同;②mainloop restart;③**heritage pass2 认领**:
   > placeMultiequals(heritage.cc:2599)→collect(307)→refinement(1890)→
   > **refineRead(1772)→concatPieces(507)** 把 304B 自由栈读替换为 280+8+8+8 的
   > PIECE 梯(seq 3501-3503),killedbycall INDIRECT 3515 是同 pass guardCalls
   > (heritage.cc:1521-1525)对 280B 影写域的独立产物;④oppool1 RulePropagateCopy
   > 折叠 COPY,CALL 直接读 CONCAT join(终态 raw 的 u0x10000a27@3503 即此件)。
   > "0x30d6:c5b/c5c"在终态不存在。Rugra master 5c610849 阶段投影实证**同链已在位**
   > (marker42 directify→marker50 认领建 3450-3452 同形梯),本节所述差异实为
   > 下游 typing/符号层而非 LOAD 存活语义。spacebase 挂载已于本日按 lane 重启用
   > (funcdata.cc:263-264 镜像),梯根 writeback URLGlob 成功;吸收剩余阻塞在 §4-4
   > 符号/打印层。
4. **打印/符号层(未修)**:golden 的 `glob.pattern[0].type = auVar21._0_4_`(
   `auVar21 = in_stack_fc78._80_24_`)形态需要:store LHS 用组符号字段路径
   (separateSymbol/establishGroupSymbolOffset/linkProtoPartial 链)+ 件 varnode 的临时名/
   partial 记法选择。Rugra 现状 `Stack_388 = Stack_388._104_4_`(RHS partial 记法已对,
   LHS 裸名)+ 每模式 2 处 CONCAT164/CONCAT204 中间态(嵌套 4+4+16 件重建未吸收)。
   group_partials census:with_piece=544(基线 452),45 件×size280 组仍在,新增
   77 件×size304 组。

CW 修复后 main 的 0x30d6 实参 IR(最终 projection):
`SUBPIECE out=n:stack:fc78..fd8c(8B×10+24B×8+4B+4B)` + 唯一空间梯腿 + setcasts CAST 链
——与 oracle raw 0x30d6:441e-4430 同形;INT_RIGHT 移位梯已消失。

## 5. 工具资产

- oracle 控制台重建命令:`cd …/cpp && make ADDITIONAL_FLAGS=-D__TERMINAL__
  decomp_opt`(CPLUS_INCLUDE_PATH/LIBRARY_PATH 指向 bfd-2.38,SLEIGHHOME=…/specs)。
- 单函数驱动:`RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=main RUGRA_STAGE_PROJ_OUT=…`
  (阶段投影)或 `--rugra-selected-function main`(C 输出)。
