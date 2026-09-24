# PRINTC-CONDBLOCK-JUNKOPS-0001 (Lane DR / wt/junk) 探查报告

日期:2026-09-23。基线:master **94f3bf58**(worktree /dev/shm/rugra-worktrees/junk,自
94f3bf58)。oracle:Ghidra 12.0.4 **e40ed130**(repo ghidra HEAD 核对相等)。只读调查,
**repo src 零改动**(根因全部落在其他被占域,按 lane 指令"登记不写");全部探针在
/dev/shm/rugra-tests/sb-junk/(wt_probe 副本,env 门控 RUGRA_JUNKPROBE/RUGRA_JUNKFUNC)。

## 0. 一句话结论

**打印侧折叠机制(copymarker→nonprinting→printc skip)在当前 master 完整工作,same-high
junk 已零残留;余 2 个 match_url `glob.pattern[3]._0_8_ = glob.pattern[3]._0_8_;` 的根因
不在打印侧,而是 ScopeLocal 把 304 字节按值参数 `glob` 装成 Register 空间整尺寸
addrtied 条目(coreaction.rs:1516-1521),把 rax 指针循环高错误符号化——修域
coreaction.rs/varmap.rs(被占,已登记 VARMAP-PARAMSTORAGE-BLOB-0001)。**

## 1. 复现基线(master 94f3bf58,CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-junk)

| 指标 | curl 全语料 | httpd 全语料 |
|---|---|---|
| 文本自赋值(Rugra) | **2**(均 match_url `glob.pattern[3]._0_8_`) | 0 |
| 文本自赋值 | 0 | 3(oracle 自己打 `sVar7 = sVar7` 等) |
| skeleton / defects / numbering | **2665 / 0 / 0** | **2331 / 0 / 0** |
| gcc 语法审计 | 81 OK / 26 FAIL(基线原状) | — |

- CL/CO 探查时的"+44 same-high 打印侧 junk"(基线 df9febd9,census same-high 91 vs 47)
  在当前 master **已消失**:CE 修复 1250e5d0(自赋值 907→2)+ 1cd11409/94f3bf58(castInput
  CPUI_COPY 臂)后,main 活 COPY 只剩 26(曾 318/9051),**15 个 same-high 全部 np=1,
  same-high np=0 打印数 = 0(main 与 match_url 双零,终态 census 逐 op 实证)**。
- main 残余 junk 精确清单(终态 11 个 np=0/oimpl=0 打印 COPY 候选中,对照 oracle 语句集):
  唯一 oracle 没有的形态 = **spill/restore 对** `p_Stack_240 = __stream;`(@0x2669)+
  `__stream = p_Stack_240;`(@0x3188)。其余(pcVar20/pUVar17/iStack_230/iVar3 族)oracle
  同位同形态打印(`pcVar20 = __haystack;` 等),非 junk。

## 2. 折叠机制双侧核对(铁律 1:先读源码)

oracle 链:merge.cc:1444-1542 `markInternalCopies`(COPY out.high==in.high→
`data.opMarkNonPrinting`,merge.cc:1461-1462;shadowed no-descend→同,1471-1475;
copyIn1/2 尾循环→`processHighRedundantCopy`,1533-1538)→ printc.cc:2696
`if (inst->notPrinted()) continue;`(op.hh:182 = marker|nonprinting|noreturn)+
printc.cc:2703-2705 out-implied skip。printc.cc:2285-2293 emitStatement /
2468-2490 emitExpression / printlanguage.cc:197-215 pushVn / pushSymbolDetail /
printc.cc:1905-1935 pushSymbol **无任何"LHS==RHS 文本"守卫**——oracle 给定同样 IR(两个
同名符号高+活非 np COPY)也会打 `x = x`。Rugra printc.rs:3308-3324(np/marker/noreturn)
与 :3341-3355(out-implied,含 VOIDCALL 例外)逐条对应,**无消费漏分支**。

## 3. match_url 2 自赋值:根因链(逐证据)

数据(终态 census,probe 输出在本目录):

- junk COPY @0x5262/@0x5328:`np=false same_high=false`,out=unique 影子(10000272/27a/282
  + rax:160 实例的 H_out),in=rax:160×7(H_in),**两个不同 HighVariable 对象**。
  copymarker 在位看见了它们(JUNKCOPYMARK same=false)——不折是**正确**的 oracle 语义
  (diff-high),oracle 同位打 `__dest = pcVar8;`(golden,两个独立局部名)。
- 两高的符号来源:各含一个 rax:160 varnode 携带 **`<SE off=0 sz=304 dyn=false sym=glob>`**
  ——8 字节寄存器 varnode 挂 304 字节静态条目。
- 挂接者(Backtrace 实证):`ActionNameVars::apply → Funcdata::link_symbol →
  handle_symbol_conflict → attach_symbol_to_vn → Varnode::set_symbol_entry`。
- 匹配来源:[JUNKMAP] `#1 sym=glob space=Register start=8 size=304 addrtied=true
  uselimit=[]`——ScopeLocal 把按值参数装成 **Register 空间 offset 8、size 304(=URLGlob
  整型尺寸)、addrtied、无 uselimit** 的条目;`find_container_entry(Register,160,1,up)`
  被 [8..311] 区间命中(rax=160 落在内),~39 个寄存器偏移全被该 blob 覆盖。
- 条目创建者:coreaction.rs:1502-1527(ScopeLocal bootstrap,`fd.funcp.is_input_locked()`
  时逐参 `scope.add_symbol(AddressSpace::Register, name, dtype, p.address, None)`)——
  **硬编码 Register 空间 + 整参数类型尺寸**;INTEGER 类参数(filename,rdi=0x38,8 字节)
  碰巧正确,MEMORY 类(URLGlob 304B 按值)错装。对照:同表 `#0 filename Register start=38
  size=8` 正确。
- oracle 为何不挂:coreaction.cc:2947-2975 linkSymbols 只对每高 nameRepresentative 调
  `Funcdata::linkSymbol`(funcdata_varnode.cc:1156+),查询按 **vn 自身地址**
  queryProperties——oracle 的 DWARF/平台参数条目在真实存储(MEMORY 类=栈槽
  in_stack_00000130),rax 查 local/global 双空 → 不挂 → varmap 默认名
  (__dest/pcVar8);同时栈槽读(oracle `glob.size / 2`)能命中条目。Rugra 的错装条目
  **两个方向都坏**:rax 指针高被错误符号化(自赋值 junk),真栈槽读反而查不到
  (输出裸 `in_stack_00000130`,oracle 是 `glob.size`)。

**修域 = coreaction.rs(ScopeLocal bootstrap 参数条目)/varmap.rs(storage 建模)**,
被占域;已登记 `VARMAP-PARAMSTORAGE-BLOB-0001`。修复要点:按参数真实存储类落条目
(MEMORY 类→栈槽 offset/size=304;寄存器类→寄存器 8B 或按 ABI 尺寸),保留
uselimit/addrtied 语义与 oracle DWARF localdb 条目一致;验收 = match_url 自赋值 0 +
`glob.size` 形态出现(对照 golden)+ 三门禁恒等。

## 4. main spill/restore 残余 + alivelist 异常(次级发现)

- `p_Stack_240 = __stream;`/`__stream = p_Stack_240;`:diff-high(stack:fdc0 temp vs
  unique __stream),oracle 侧同族并入同一高后 same-high→copymarker np(或 trim 消除)。
  归 merge/copyTrims 域(MERGE-COPYNOISE 系既有账)。
- **bookkeeping 异常(新证据)**:spill 半 @0x2669 **不在终态 alivelist census 里却仍被
  打印**——blockaction.rs:8354-8391(ActionFinalStructure 内 RUGRA-GLUE,"Remove
  unreachable ops after unconditional BRANCH or RETURN",注释自认无 oracle 对应)只从
  alivelist 删 op,**不置 DEAD、不清 block 链接**:printc 按 block+is_dead 走仍打印,
  而 alivelist 消费者(copymarker/probe census)看不见。后果双面:① 任何 alivelist 驱动
  的后置 Action 对这些 op 失明;② census 类审计失真。已登记
  `BLOCKACTION-ALIVELIST-GLUE-0001`(修域 blockaction.rs,被占)。

## 5. 三门禁与验证状态

- 本 lane **零 src 改动**,门禁 = 基线恒等实测:curl **2665/0/0**、httpd **2331/0/0**
  (compare_ghidra.py --summary-only,输出在本目录)、`--func main` defects=0。
- 双 MATCH 保持:无行为改动,逐函数 fixture 面无扰动。
- printc.rs 消费面复核:主循环门(:3308-3324/:3341-3355)与 oracle printc.cc:2694-2722
  逐条对应;is_block_body_empty(:4010-4037,legacy fallback)同门语义。**printc 域无缺陷,
  本 lane 不写。**

## 6. 可复现清单(本目录)

- `wt_probe/`:探针副本(merge.rs JUNKCOPYMARK/JUNKFINAL/JUNKMAP、funcdata.rs hook、
  varnode.rs set_symbol_entry backtrace;env RUGRA_JUNKPROBE/RUGRA_JUNKFUNC)。
- `rugra_main_before.c` / `rugra_match_url_before.c` / `rugra_curl_all_before.c` /
  `rugra_httpd_all_before.c` + 各 `.stderr.log`(RUGRA_DUMP_FUNC IR dump)。
- `probe_main.stderr.log` / `probe_match_url{,2,3}.stderr.log` /
  `probe_se_match_url.stderr.log` / `probe_map_match_url.stderr.log`:census/挂接
  backtrace/条目表证据。
- 基线构建:CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-junk(probe 用 sb-junk-probe)。

## 7. 登记(见 docs/TODO_BOARD.md 同步更新)

1. `PRINTC-CONDBLOCK-JUNKOPS-0001`:**打印侧结论关闭**——折叠机制工作,same-high 打印
   junk=0;余量路由 VARMAP-PARAMSTORAGE-BLOB-0001(match_url ×2)与 merge/copyTrims 系
   (main spill 对)。
2. `VARMAP-PARAMSTORAGE-BLOB-0001`(新,P2):coreaction.rs:1516 参数条目硬编码 Register
   空间+整类型尺寸;双方向破坏(指针高错误符号化+栈槽读失名);owner 待派。
3. `BLOCKACTION-ALIVELIST-GLUE-0001`(新,P3):blockaction.rs:8354-8391 仅删 alivelist
   的 glue;alive-per-flags op 对 alivelist 消费者失明;owner 待派。
