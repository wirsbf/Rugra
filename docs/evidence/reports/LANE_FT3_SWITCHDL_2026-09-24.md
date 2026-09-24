# Lane FT3 终报 — DRIVER-SWITCHD-LABEL-0001(switchD_caseD 拼写族驱动符号层)

- **Worktree**: wt/switchdl @ /dev/shm/rugra-worktrees/switchdl,基(亲父) 9458a61b,交付 commit **ff971049**(5 files, +152/-1)
- **前史**: FT/FT2 两代中断,worktree 曾被清空;FT2 未提交实现经 `/dev/shm/rugra-tests/sb-switchdl/dirty-backup/`(prettyprint.rs/curl_decompile.rs/httpd_decompile.rs)字节级复原,重建后输出与 FT2 归档(curl_cur.c/httpd_cur.c)diff 恒等 —— 复原完整性已证。
- **Oracle**: Ghidra 12.0.4 e40ed130(锁定);本 session 亲读 jumptable.cc:2764-2791(JumpTable::encode)/2545-2568(switchOver defaultBlock=max-count 落点)、printc.cc:3160-3200(emitLabel→queryCodeLabel)、database_ghidra.cc:308-325(findCodeLabel 远端查询)。printc.rs 零改动(如任务书预期)。

## 1. 命名规则(交付物)

```
switchD_<dispatch 8位hex>_caseD_<case值hex无填充小写>   # 每个 label≠NO_LABEL 的 addresstable 项,在其 dest 建名;共享目标首项获胜(or_insert)
switchD_<dispatch 8位hex>_default                       # 仅当 default 目标无 caseD 落点;default_block≥0 时 = BRANCHIND 母块 out-edge[default_block] 目标块起始地址
dispatch = ANALYZE_HEADLESS_IMAGE_BASE(0x100000) + jt.opaddress
```

插入驱动的 code_labels 层(EX2 LAB_ 同机制),覆盖 LAB_ 缺省;**RUGRA_MIRROR=1 路径整块跳过**(投影零移动的构造性保证)。prettyprint P9(goto→尾调用改写)排除 `switchD_` 前缀——该族是 LABEL goto,双 golden 语料 0 处 `return switchD`,不排除会产出非法 `return switchD_...();`。

## 2. 前后对比(基线=亲父 9458a61b)

| 门禁 | 前 | 后 | 判定 |
|---|---|---|---|
| curl(skeleton/defects/numbering vs golden) | 2145/0/0 | **2135/0/0** | glob_set 71→61,拼写族收敛 |
| httpd(vs golden) | 2057/0/0 | 2057/0/0 | **输出与基线字节恒等**(diff 空) |
| gcc audit(fail 集合) | 82OK/25FAIL, 8OK/21FAIL | 同 | 无新增失败 |
| 三投影(MIRROR=1) | — | next_url **MATCH**(335/96457)+match_url **MATCH**(340/80385)+parseconfig.constprop.0 **与基线字节恒等**;getparameter 指纹 stage186/opline367=FK/FO 谱系基线(既有) | 全保持 |

curl 具体位点:LAB_00104c5e→`switchD_00104c45_caseD_5e`、code_r0x00104c7c→`switchD_00104c45_caseD_7d`、LAB_00104d04→`switchD_00104c45_caseD_5d`(3 标号定义+7 goto 位,全与 golden 拼写一致);getparameter 0x104030→`switchD_00103fd5_caseD_4e`(拼写按分析器规则正确;skeleton 不动——golden 该处是结构化 `case 0x4e:`,结构残差属 ACTION-REWORKFIX-STRUCT-0001 域)。

## 3. 超范围如实登记(TODO 行已同步)

1. **httpd 122 处 switchD 位点零收敛**:全部位于 Rugra 结构器不产 goto 桥的 switch(case 块被内联直落/if 链;golden 是 `switch(...)`+`goto switchD_...` 桥形,如 main 0x12ba94 caseD_40 的 apr_getopt 块)。二进制确认 0x2ba94 `notrack jmp *%rax` 为真 jumptable;收敛被结构域阻塞,本层就绪待结构器产出同拓扑。
2. **golden httpd 3 处 `switchD_00154265::default(void)` 等独立函数名**:分析器函数符号通道(非 LABEL 层),未实现,登记待认领。
3. FT2 工件 run_projections.sh 第三投影函数名误标(实投 getparameter 存入 m_parseconfig 文件;/dev/shm 工件,非仓库文件;指纹对照仍有效)。

## 4. 证据

`/dev/shm/rugra-tests/sb-switchdl/`:ft3_*.c/err(交付复跑)、parent_* 基线、m_*.projection+bisect_*.txt、dirty-backup(FT2 复原源)、curl_cur.c(FT2 归档,恒等锚)。commit ff971049(hooks 全绿:gate health/docs 同步/annotations/refs)。
