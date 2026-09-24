# VARMAP-PARAMSTORAGE-BLOB-0001 (Lane DX / wt/paramblob) 交付报告

日期:2026-09-23。基线:master **52c9abd5**(worktree /dev/shm/rugra-worktrees/
paramblob)。oracle:Ghidra 12.0.4 **e40ed130**(ghidra symlink HEAD 核对相等)。
**commit 0a097498**(branch wt/paramblob)。CARGO_TARGET_DIR=/dev/shm/rugra-targets/
sb-paramblob(已按回收纪律清除)。

## 0. 一句话根因

ScopeLocal bootstrap 把 input-locked 参数符号硬编码装进 **Register 空间+整参数类型
宽度**,MEMORY 类按值参数(match_url 304B `URLGlob glob`)变成 Register:8/size304
的 addrtied blob,`find_container_entry` 的 [start..last] 包含判定吞掉 rax:0xa0
指针循环高(错误符号化 → 2 个 `glob.pattern[3]._0_8_` 自赋值 junk),而真栈槽读
(stack:0x130 = glob.size 字段)反查不到(裸 `in_stack_00000130`)。

## 1. Ghidra oracle 语义(铁律 1,本 session 完整读过)

- `coreaction.cc:2274-2295 ActionRestructureVarnode::apply`:l1 为 per-Funcdata
  持久 ScopeLocal;平台参数符号在 scope 构造前由 Program DB(localdb)装好——
  **apply 本体不装参数符号**,条目带真实存储空间。
- `varmap.cc:864-875 MapState ctor`:paramRange 逐段从分析 range 移除——参数
  存储区归参数符号所有,restructure 不在其上建局部符号。
- `varmap.cc:1389-1448 fakeInputSymbols`:stack 输入 varnode 查到
  function_parameter 符号即 skip(不建 in_stack 假符号)。
- `funcdata_varnode.cc:938-990 syncVarnodesWithSymbols`:**只步进 stack 空间**,
  `findOverlap` 包含判定 + `getSizedType` 字段投影(栈参数 typelock 流入路径)。
- `coreaction.cc:2940-2985 linkSymbols`:逐 nameRepresentative 按其**自身地址**
  queryProperties——寄存器 varnode 查不到栈条目,故 oracle 侧 rax 用默认名。

坐标系双侧核对:Rugra 栈锚 = entry-rsp 相对(首栈参 +8),与模型 ParamEntry 分配
的 p.address=8 同系;`mov 0x178(%rsp),%ecx` − prologue 0x48 = stack:0x130 =
&glob.size(struct 偏移 0x128+基 8);`lea 0x50(%rsp),%rsi` = &glob = stack:8。
glob 占 [8, 0x138)。

## 2. 修复

`src/coreaction.rs`(bootstrap 段):逐参携带 `ProtoParameter::address_space`,
Register 类照旧(Register 偏移/寄存器宽),**Stack 类落 Stack:模型偏移+整类型宽**
[8,0x138);寄存器 typelock 手动支腿改按 `space == Register` 门控(栈参数走
sync_varnodes_with_symbols 的 getSizedType 投影,与 oracle 同路)。varmap.rs
**零改动**(查询/同步链本已忠实,缺陷仅在 bootstrap 落位)。

## 3. match_url 前后形态对照

| 项 | before(52c9abd5) | after(0a097498) | oracle golden |
|---|---|---|---|
| 自赋值 junk | **2**(`glob.pattern[3]._0_8_ = 同名;`×2) | **0** | 0 |
| 栈槽 size 读 | `in_stack_00000130 / 2` | **`glob.size / 2`** | `glob.size / 2` ✓ |
| rax 循环高 | 错挂 `glob.pattern[3]._0_8_` | 独立局部 `__dest`/`pcVar9` | `__dest`/`pcVar8` 同构 |
| 索引装载 | `*(int2 *)(&0x68 + iVar6)` | 同(byte-identical) | `glob.pattern[iVar5]…`(域外残差) |
| 全语料 in_stack 名集合 | 21/3/4/+1(param 槽) | 21/3/4(与 oracle 全等) | 21/3/4 |

## 4. 三门禁 + 验证

| 门禁 | before | after | 判定 |
|---|---|---|---|
| curl 全语料 | 2665/0/0 | **2643/0/0**(-22,全部来自 match_url 76→54) | ✓ 改善 |
| httpd 全语料 | 2331/0/0 | **2331/0/0** | ✓ 恒等 |
| gcc 语法审计 | 81 OK/26 FAIL | **81 OK/26 FAIL** | ✓ 恒等 |
| `--func match_url` | 76/0/0 | **54/0/0** | ✓ |
| `--func main` | 605/0/0 | **605/0/0** | ✓ 恒等 |
| `--func next_url`(双投影) | 103/0/0 | **103/0/0** | ✓ MATCH 保持 |
| 其余 123 函数 | — | **byte-stable**(逐函数 diff 恒等) | ✓ 零波及 |
| cargo test --lib 串行 A/B | 18 失败(已知 flaky 族) | **同一 18 集合,逐名恒等** | ✓ 零新失败 |

并行模式失败数波动(HEAD 18-23,fix 23-27)为全局 TypeFactory 单例并发干扰的既有
现象,串行 A/B 判定集恒等证明非本改动引入。

## 5. 未决(登记,域外)

- **RULEACTION-STACKIDX-FOLD-0001**(新登记,TODO_BOARD):match_url 索引装载
  `*(int8 *)(&0x60 + iVar6)` vs oracle `glob.pattern[iVar5].type`——spacebase
  ADD 链被折叠成裸常量,修复前后 byte-identical(非本 lane 引入);修域
  ruleaction/disasm(被占不写)。
- main spill/restore 对与 BLOCKACTION-ALIVELIST-GLUE-0001 维持 Lane DR 原判。

## 6. 产物(本目录)

- `curl_after.c`/`curl_final.c`(byte-identical)+ `httpd_after.c` + 各 stderr.log
- `match_url_before_body.c`/`match_url_after_body.c` + diff
- `fails_head.txt`/`fails_fixed.txt`(串行 A/B 失败集,恒等)
- `commit_msg.txt`(含 ## Alignment Evidence 四类 4/4 + ## Differential)
