# Lane GL 终报 — glibc 原型参数名族收口(GLIBC-PROTO-PARAMNAME-0001)

- worktree: /dev/shm/rugra-worktrees/glibcproto, branch **wt/glibcproto**, 基 = 亲父 **abbde651**(亲测)
- oracle: Ghidra 12.0.4 e40ed130(源码引证)+ **Ghidra 12.1.2 headless 实证**(/data/ls/DiffClip/tools/ghidra_12.1.2_PUBLIC;12.0.4 headless 构建物已随重启丢失,12.1.2 对 curl main 输出与 12.0.4 canon golden **逐字一致**后方用作机理诊断)
- 交付 commit: 见 git log(branch tip)

## 1. 任务假设修正

派发词假设"golden 调用点带参数名而 Rugra 缺失"——**实测方向相反**(GI2 detail 文件
亲证):canon main 是裸变量名,Rugra 多出 libc/DWARF 形参名局部。canon 并非无机制,
而是**少而特定**:`__stream/__stream_00` 恰为流入 `fclose(FILE* __stream)` 的两个
FILE* 局部。

## 2. 复现定形(任务①)

| 侧 | main 的 libc/DWARF 参数名局部 |
|---|---|
| canon 12.0.4 golden | `__stream×6, __stream_00×8`(仅此两个) |
| direct-runner(裸 BFD) | 无(无 libc 签名) |
| Rugra 亲父 abbde651 | `__haystack×15, __ptr×10, __stream×8, __filename×7, __s×4, __stream_00×8` + DWARF `nextarg` |

样本 8+(strstr/fopen/fclose/free/malloc/strrchr/__sprintf_chk/fileno/gets 形参链);
canon 跨函数旁证:my_fwrite `__s`/my_get_line `__dest`/match_url `__dest`/
file2string `__ptr`/parseconfig `__stream+__ptr`/progressbarinit `__nptr`——机制
在 canon 全语料开火,main 只剩 FILE* 两例。

## 3. 机制(任务②,oracle 源码+12.1.2 实证)

1. `ActionNameVars::lookForFuncParamNames`(coreaction.cc:2853-2897):锁定
   callspec 的形参名→推荐给**未命名符号**的局部;命名循环挡板
   cc:2887 `high->getNumMergeClasses() > 1`(投机合并多类不命名)。
2. 多类来自 `ActionMergeType`→`mergeByDatatype`→`mergeLinear`
   (coreaction.hh:414 → merge.cc:272-292/359-402):**类型指针恒等**
   (merge.cc:387 `ct == high->getType()`)分组 + 覆盖不相交投机合并。
   canon main 的多区复用指针临时(RAX 装载)合并成多类→不命名;寄存器常驻
   单类值(R14/R15 FILE*)→命名 `__stream`。12.1.2 debug XML 旁证:canon headless
   的 main DB 符号表含 DPID 预命名 `local_*` 栈符号(这些槽的值永不参与该命名),
   而 `pcVar*` 临时在打印期合成=符号全程未名,唯一能挡它们的就是合并类挡板。
3. **Rugra 根因**:`parse_c_type`(libc 24 表)每 callsite `Arc::new` 裸铸类型→
   身份碎片化→同型分组不成组→临时恒单类→被过命名。次要碎片点:驱动 cspec
   工厂为 per-process 裸建(与 DWARF 侧 shared_default 不同域)、`void_type`
   裸建、DWARF char 臂裸建。

## 4. 修复(任务③,写域内)

`src/debugproto.rs` + `examples/curl_decompile.rs`:
①`parse_c_type` 全面走 `TypeFactory::shared_default()`:基础拼写
`find_by_name` 名树(grammar.cc:2989 镜像)→`get_base_named`/findAdd
(type.cc:3412);指针层 `get_type_pointer` 3 参匿名重载
(grammar.cc:2402-2411→type.cc:3867-3875);②`void_type`→`get_type_void`
单例;③`dwarf_base_type` char 臂→`intern_named`;④curl 驱动
`build_worker_architecture` 的 cspec data_organization 解码目标改
`shared_default()`(= `Architecture::ensure_types` 既有 canonical 口径;管线/
libc/DWARF 三通道一域,镜像 Ghidra 每 Architecture 一工厂 type.cc:3106)。

## 5. 前后数字(任务④,亲测 fast-release)

| 门禁 | 前(abbde651) | 后 |
|---|---|---|
| curl E2E canon | 1740/0/0 | **1561/0/0**(−179) |
| httpd E2E canon | 1698/0/0(=任务预期) | **1698/0/0**(驱动零触碰) |
| curl main 参数名 | 多 5 名(48 行族) | **只剩 canon 同款 `__stream/__stream_00`** |
| 逐函数 | — | 改善 6(next_url −53/glob_word −21/match_url −19/my_get_token −14/glob_set −12/main −5);**回退 2**(my_get_line +33/glob_range +7,编号级联,已登记 `MERGE-SAMETYPE-COVER-PARITY-0001`) |
| 五投影(RUGRA_MIRROR=1) | MATCH×5 | **MATCH×5 保持**(非 META 0 行差) |
| 双跑确定性 | — | cmp 恒等 |
| gcc 审计 | curl 104/20 | **104/20 == 前值** |
| 单测 | — | debugproto 13/13, coreaction 60/60, merge 8/8, typefactory 60/60 |
| file2string/parseconfig | 欠命名(基线既有) | 仍欠名(对向 merge 残差,同 TODO) |

## 6. 残差移交

`MERGE-SAMETYPE-COVER-PARITY-0001`(merge 域,机制 C 白名单):
- 过并:my_get_line/glob_range——canon 保持分离的 char* 临时对在统一身份后被并
  (Rugra 覆盖判交=时间戳级粒度 vs Ghidra 块区间集,同块交错判定更粗);
- 欠并:file2string `__ptr×8`/parseconfig `__stream×8+__ptr×7`(canon 命名而
  Rugra 分组/覆盖差未达单类命名路径)。

## 7. 回收

- 终报归档:/dev/shm/rugra-reports/sb-glibcproto/LANE_REPORT_GL.md(本文件)。
- /dev/shm/rugra-tests/sb-glibcproto/ 与 /dev/shm/rugra-targets/sb-glibcproto/
  保留至 root 集成门禁复跑后清扫(未集成不先删,防止 root 复验全量重编)。
