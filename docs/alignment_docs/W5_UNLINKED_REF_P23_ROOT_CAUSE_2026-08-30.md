# W5 审计:POSTFIX-RETIRE-0001 P23(UNLINKED-REF 域)逐语句根因账本

- Agent: w-w5 | worktree: /home/wirs/.cache/rugra-w2-w5 (detached master ec5e3167)
- oracle: ghidra 12.0.4 @ e40ed13014025f82488b1f8f7bca566894ac376b (symlinked)
- 基线: curl 3090/0/0 + httpd 2274/0/0;P23 = curl 8 行 / httpd 7 行(当前 runner 口径)
- 方法:RUGRA_POSTFIX_RAW_DIR 双侧 in/out 落盘 → 逐行配对回填语句 → RUGRA_DUMP_FUNC/
  RUGRA_HERITAGE_TRACE/DBG 插桩定位 varnode 源头 → 读 Ghidra 对应函数定差异。

## P23 是什么

`EmitNoMarkup::backfill_missing_locals`(prettyprint.rs:2123,RUGRA-GLUE,Ghidra 无对应物)
对函数体内使用但未声明的 `*Var*`/`register0x…`/`unique0x…`/`ram0x…` token 注入
`int/long X;` 声明。计数>0 的唯一原因是 emit 输出里出现了**无 HighVariable 名字的
varnode 引用**——即 printc 落入 `pushUnnamedLocation`(printlanguage.cc:244
`sym==0 → pushUnnamedLocation(high->getNameRepresentative()->getAddr())`)。
oracle 侧该 arm 几乎不可达:`ActionNameVars`(coreaction.cc:2928-3001)对每个
nameable high 调 `Funcdata::linkSymbol`(funcdata_varnode.cc:1156-1191)——
无重叠符号且 `!isPersist()` 时在 ScopeLocal `addSymbol("")` 建符号,再由
`buildDefaultName`→`buildVariableName`(database.cc:1756)补 lVar 族名;
persist(全局)varnode 则靠 global scope 的 `findContainer` 命中 DWARF/ELF 全局符号。

## 家族账本(curl 8 行 + httpd 7 行,共 5 族)

### F1 — nodeSplit 克隆输出丢失地址空间(curl 3 行:_init/my_get_token/next_url;httpd 0 行)

证据链:
1. `Heritage::guardReturns` persist 尾(heritage.cc:1676-1691)对每个 live RETURN 建
   `COPY out@(range)=…`,`out` addr-force 于**range 自己的空间**——Rugra 移植正确:
   `H-GRET-OUT copy@0x37e3 out=vn#1714(Ram:17510,size=8)`(trace 实测)。
   全局 `save`(0x17510)的 range fl=mapped|addrtied|persist
   (guard_query_properties 分支 3,Ram→persist,对齐 database.cc:1271-1276
   finalscope=global 的 persist 位)。
2. `ActionUnjustifiedInput`(blockaction.cc:2316)随后 nodeSplit 复制 return 块;
   `CloneBlockOps::buildVarnodeOutput`(funcdata_block.cc:992-1004,oracle 以
   `origvn->getAddr()` 全地址建克隆)在 Rugra(funcdata.rs:16519-16523)走了
   `new_varnode_out` 适配器——**Address 不带 space、适配器钉死 Register**,
   ram:17510 的 persist 写回被克隆成 register:17510。
3. 克隆后:persist 位被拷贝(vflag_mask 含 PERSIST)→ linkSymbol 的
   `if (!isPersist())` 建符号臂被跳过(funcdata_varnode.cc:1174),而
   `query_global_symbol_hit` 又正确地只认 Ram(funcdata.rs:1359)→ 无符号 →
   `register0x00017510` → P23 回填 `long register0x00017510;`。
   oracle 同路径:克隆在 ram:17510、persist+addrtied → stackContainer 终结于
   global scope 命中 DWARF `my_get_token::save` → 打印 `my_get_token::save = line;`
   (golden 1125-1210 区段逐语句可见)。

修复方案(funcdata.rs 归 scopefix2 owner,补丁已验证:/tmp/w-w5-f1-fix.patch,
29 行):`build_varnode_output` 读 `orig_vn.address_space`,以
`fd.vbank.create_def_with_space(size, space, addr, &clone_op.0)` 替代
`fd.new_varnode_out`,补 `assign_high`/`check_for_laned_register`/
`set_varnode_properties` 三条尾(形态同 condexe.rs:612
`new_varnode_out_with_space`——condexe 自己的两个调用点早已走保空间版)。
**验证结果:curl P23 8→5,defects=0/numbering=0 保持,skeleton 3090→3085(纯降);
httpd 不受影响(其 P23 非本族)。**

### F2 — myprogress 浮点 CAST 链晚生 temp 无名(curl 4 行:unique0x10000235/239/251 + register0x00001200)

IR 证据(myprogress dump):
`FLOAT_INT2FLOAT out=unique:10000235(implied) = long` →
`CAST out=fVar6(register:1240,显式) = unique:10000235`,打印
`fVar6 = (float)unique0x10000235;`。unique:100002xx 是 CAST/浮点链在管线后期
新分配的 temp(ActionNameVars 之后创建,从未进入命名);
register:0x1200 = XMM1_Qa 同链。oracle 对应形态:
`fVar10 = (float)uVar8 / (float)(dltotal + ultotal);`(golden 1159 行附近)——
转换在表达式内联,无中间语句。根因横跨 coreaction(CAST 插入/显式化,
coreaction.cc:2583-2712 对应区)与 printc(CAST 输入按名打印而非 implied 内联),
均不在 W5 write-set。

### F3 — condexe/lifter 小偏移 unique temp 泄漏为 LOAD 地址(curl 1 行:next_url unique0x00009100)

`while (… *(( *)unique0x00009100) …)`——LOAD 的地址输入是 0x8f00/0x9100/0x9d00
小偏移 temp 区(x86_lift alloc_tmp 族)残留,数据流未收敛。lifter/disasm 与
condexe 域,不在 W5 write-set。

### F4 — httpd RAX(register0x00000000)循环条件变量无名(3 行:ap_getparents/ap_pregsub/ap_update_vhost_from_headers)

`} while (register0x00000000 != …);` —— RAX 高无名。golden 对应处全部是命名局部
(ap_getparents 的 cVar6/uVar8 族,golden 5655-5700)。httpd runner 无 op 级
RUGRA_DUMP_FUNC(只有结构树),IR 级断点待 fixture(见“后续”节)。

### F5 — httpd main 两行:ram0x000a6688(无名 RAM 槽)+ register0x/unique0x000a5c49

`iVar3 = ram0x000a6688;`——Rugra 的全局符号层在该 .bss 地址无条目(analyzeHeadless
oracle 侧有全局符号);0xa5c49 是 text 段地址,register/unique 双空间同名偏移,
疑 call-target/spacebase 残留。需 database.rs 全局符号播种核对,不在 W5 write-set。

## 结论与移交

1. **P23 的 15 行没有一个的治本点落在 varmap/ruleaction/typeop**(W5 预设"上游缺陷
   在 varmap/类型层"经逐语句证伪):F1 在 funcdata.rs 克隆路径(补丁已验证,
   curl -3 行),F2 在 coreaction/printc,F3 在 disasm/condexe,F4/F5 需 httpd
   fixture 补 IR 证据。
2. F1 补丁(29 行,/tmp/w-w5-f1-fix.patch)建议主 Agent 串行集成时移交流程:
   funcdata.rs 属 scopefix2;机制 C 白名单(coreaction 侧 ActionNameVars 无改动,
   funcdata 克隆路径非白名单文件,但建议照白名单流程复核)。
3. PTRARITH 族(P25 fix_pointer_arithmetic / P26)当前 0/0,无退役工作。
4. 顺带发现的未移植缺口(登记,未修):`RuleStoreVarnode` 尾部
   `ScopeLocal::markNotMapped`(ruleaction.cc:4337-4339 ↔ ruleaction.rs TODO(scopelocal)
   + varmap.cc markNotMapped)——与本波 P23 无因果(storeUnmapped 罕见),留给下波。
