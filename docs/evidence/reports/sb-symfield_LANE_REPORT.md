# Lane DV: DWARF-SYMFIELD-TYPESTATE-0001 — sb-symfield 交付报告
Commit: a88a694b (wt/symfield, base master 94f3bf58)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c

## 类型态断点(一句话)
stdout/stdin/stderr 在 curl 的 DWARF 只有 declaration(无 DW_AT_location),
DebugGlobalDatabase 跳过它们→驱动 ELF 回退种成匿名 `undefined *`+`@@GLIBC_2.2.5` 名;
同时 parse_type_names 的 typedef 条目直接解析 DW_AT_type 目标,`FILE` 落成
`struct _IO_FILE`——符号无类型+typedef 名丢失双因素,产生 `(_IO_FILE *)stdout@@` 形。

## 修复(debugproto 域,SYMFELD-①)
1. parse_type_names: DW_TAG_typedef 经 resolve_type typedef 分支物化(保 FILE 拼写)。
2. parse_elf: walk 收集 external 声明 + copy_reloc_object_symbols(goblin
   R_X86_64_COPY/STT_OBJECT/@@剥离)绑定地址。影响集恰为 stdio 三符号;httpd 惰性。

## main 前后(→ golden 对齐)
- `__stream = stdin@@GLIBC_2.2.5;` → `__stream = stdin;` (golden 609) MATCH
- `__stream_00 = (_IO_FILE *)stdout@@GLIBC_2.2.5;` → `__stream_00 = stdout;` (golden 895) MATCH
- `(_IO_FILE *)0x0` → `(FILE *)0x0` (golden 多处) MATCH
- `pFStack_200 = (FILE *)stdout;` cast 重现 (golden 896 heads.stream) MATCH
- `int fclose(_IO_FILE *__stream)` → `int fclose(FILE *__stream)` (golden 124) MATCH

## 三门禁
- curl: defects=0 numbering=0 skeleton 2665→2614 (main 605→583; 10 函数改善 0 回退)
- httpd: defects=0 numbering=0 skeleton 2331 == 基线
- 双 MATCH: next_url/match_url 字节级不变 (skeleton 103/76)
- gcc 审计 82OK/25FAIL (基线 81/26); lib 测试 --test-threads=1 18 失败==基线

## 未决(②③,修复域=coreaction/unionresolve,已登记 TODO)
② `glob.pattern[8].content.Set.elements = (undefined8)in_stack_...fd90` vs golden
   `(char **)`: Rugra 在该 STORE 插 union_a49 8B PartialUnion cast(get_exact_piece
   union 臂;dump op@0x30d6 `CAST(PartialUnion)=in_stack_fd90`),oracle 经
   ScoreUnionFields.derefPointer 钻 Set→elements@0 尺寸匹配后 cast 叶子 char**。
③ `glob._296_8_ = (undefined8)uVar32` vs golden 裸 `uVar29`: PartialStruct 片同类。

## 工件
curl_main_before.c / curl_main_after.c / main_before_after.diff /
curl_dump_before.err / curl_dump_after.err / httpd_after.c /
perfunc_before.txt / perfunc_after.txt / probe_types.rs / commit_msg.txt
