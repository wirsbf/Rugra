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

## 4. 精确分歧点(待修)

`SPLITCOPY_BIG` probe:280B 栈读 `in_input=false in_written=true`。
Ghidra 中该域整体落在 **in_stack 输入影子**(读先于写在栈域),件为
SUBPIECE/字段载入的栈地址输出;rugra 中 280/304B 读被当作"已写"
(heritage 把 8B 循环 store 连进了大读,或 guard_input 的 concat_pieces
统一写出),splitCopy 的 input-guard(subflow.cc:2390 ↔ rugra subflow.rs:6208
**两侧守卫一致**)不触发,拆分走寄存器域重组。

候选修复面(按依赖序):
1. heritage rename_recurse/大读输入晋升:286/304B 自由读在 Ghidra 侧成为
   input(见 heritage.cc:2498-2503 varstack 空→setInputVarnode);rugra 侧
   被判 written。用 stage-drill 双侧阶段 bisect 定位首个分歧阶段。
2. 拆分后件的落点:oracle 的件是栈地址 varnode(buildInSubpieces/
   buildPointers),打印为 in_stack 部分读;rugra 件在 join/寄存器。
3. 命名链:callsite param NAME_LOCKED → makeRec(需 high 非 addr-tied)。

## 5. 工具资产

- oracle 控制台重建命令:`cd …/cpp && make ADDITIONAL_FLAGS=-D__TERMINAL__
  decomp_opt`(CPLUS_INCLUDE_PATH/LIBRARY_PATH 指向 bfd-2.38,SLEIGHHOME=…/specs)。
- 单函数驱动:`RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=main RUGRA_STAGE_PROJ_OUT=…`
  (阶段投影)或 `--rugra-selected-function main`(C 输出)。
