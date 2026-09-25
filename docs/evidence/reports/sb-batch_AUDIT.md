# targets.json 交叉审计 (Lane T)

- 审计对象: `/dev/shm/rugra-tests/sb-batch/targets.json`(Lane S 产物,153 条 = curl 124 + httpd 29)
- 审计时间: 2026-09-22;仓库只读(`/home/ls/Rugra`,HEAD 与 Lane S 基线同源 `0acde30`),未跑构建
- **结论速览: 发现并修正 1 类真实数据错误(44 处 skeleton 值);entry_addr 零错误;curl 名单与 golden 逐块 1:1;httpd 29/29 全在 golden;修正后 skeleton 抽检 10/10 复现。**
- 修正后产物: `targets.json`(原子写,原版备份于 `targets.json.lane-s-orig`;修正脚本 `fix_targets_dup.py`,逐条变更见 `audit_fix_report.txt`)

## A. curl 124 函数名单 vs `tests/golden/ghidra_curl_1204.c`

方法: golden 头行解析 124 条;targets 124 条按 GCC 后缀剥离键双向比对;再以头地址( golden 侧重基 `-0x100000`)做**逐块多重集**比对。

| 检查项 | 结果 |
|---|---|
| golden 函数块总数 | 124(与 targets 相等) |
| targets 有而 golden 无(多) | **0** |
| golden 有而 targets 无(漏) | **0** |
| 仅后缀差异的名字 | 4: `getparameter.constprop.0` / `parseconfig.constprop.0` / `file2string.part.0` / `SetHTTPrequest.part.0`(golden 侧 stripped 名,预期) |
| **逐块地址多重集比对** | **完全相等**(124 块一一对应,0 多 0 漏) |

名单结构: 80 个唯一名 = 36 个单名块 + **44 个名字各出现 2 次**(88 块)。重名不是数据错误: 每个 UND import 符号在 Rugra 输出与 golden 中都有两个块——

| 块类 | 地址区 | 条数 | 说明 |
|---|---|---:|---|
| `plt_stub` | 0x22e0–0x2590(.plt.sec) | 44 | stub 块,golden 地址与此一致 |
| `external_import` | 0x19000–0x19178(external block) | 44(对内)+ 4(单名) | 平台构件块(`_ITM_*`/`__gmon_start__`/`__libc_start_main` 仅此类) |
| `init_plt_chunk` | 0x2000–0x22e0 | 2 | `_init` 与 `FUN_00102020`(无符号名 .plt 首项) |

后缀折叠边界已精确核verified: golden 有**两个** `SetHTTPrequest` 条目(`0x103c50` 43 bytes 与 `0x104980` 24 bytes),分别对应 ELF 独立符号 `SetHTTPrequest.part.0` @0x3c50 与 `SetHTTPrequest` @0x4980;targets 同时收录两者,无折叠丢失。

## B. httpd 29 vs golden 2010

- 29/29 按名字全部在 golden 内(0 缺失);`golden_addr - 0x100000` 与 `entry_addr` 29/29 完全一致。
- golden 其余 1981 条(319 PLT thunk + 742 external import + 918 未选 .text + 2 init,sb-corpus 分类)不在本批范围,属预期: httpd 批只覆盖 Rugra 驱动当前输出。
- httpd 29 无重名、无后缀名。

## C. entry_addr 复核(nm -D / readelf -sW)

范围与纪律: 修正后 rank **top-20 curl + top-10 httpd**;`addr_source="rugra_header_und"` 的条目归加固 lane,标记 out-of-scope 不计。

| 批 | 复核(非 UND) | 结果 | UND(oos) |
|---|---:|---|---:|
| curl top-20 | 17 | **17/17 OK**(readelf -sW defined FUNC 值逐一相等) | 3(`__ctype_b_loc@0x2580`、`fclose@0x2360`、`fgets@0x23d0`,均 plt_stub) |
| httpd top-10 | 10 | **10/10 OK** | 0 |

nm 交叉: `nm -D --defined-only examples/curl` 0 条(curl 动态符号全 UND,defined 符号仅在 .symtab,nm 全表可见);httpd nm -D 474 条 defined FUNC,与 readelf 一致。

### C.2 留给 UND 加固 lane 的情报(93 条,本审计不改动)

- **44 个 plt_stub 块的 `entry_addr` 已经是真实 .plt.sec stub 地址**(0x22e0–0x2590),且与 golden 头地址(重基后)逐一相等——golden 用的也是 stub 地址。这些值**不要改**。
- **48 个 external_import 块(0x19000–0x19178)在 ELF 中不存在对应符号/地址**(readelf 解析不到;该区是 Ghidra/Rugra 的 external-block 虚拟建模),`rugra_header_und` 回落是唯一可用来源;golden 侧同地址(逐块多重集相等已证明两侧建模一致)。
- `FUN_00102020` @0x2020 为 .plt 首项真实地址。
- 加固时应保留 `block_class` 字段区分两类,避免把 external 地址误"纠正"成 stub 地址(会破坏与 golden external 条目的对齐)。

## D. skeleton 抽检(10 条,独立通道重跑 `compare_ghidra.py --func`)

选样覆盖单名 top、重名对(修正前后值均验)、httpd 大小两头:

| 条目 | targets 值 | 工具复测 | 判定 |
|---|---:|---:|---|
| curl/main@0x25a0 | 1248 | 1248 | MATCH |
| curl/getparameter.constprop.0@0x3f00 | 869 | 869 | MATCH |
| curl/next_url@0x4ff0 | 144 | 144 | MATCH |
| curl/glob_set@0x4bc0 | 91 | 91 | MATCH |
| curl/my_fwrite@0x3460 | 16 | 16 | MATCH |
| curl/__ctype_b_loc@0x2580(重名 stub) | 11 | 11(段序 1/2) | MATCH |
| curl/free@0x22f0(重名 stub) | 5 | 5(段序 1/2) | MATCH |
| curl/maprintf@0x23b0(重名 stub) | 4 | 4(段序 1/2) | MATCH |
| httpd/ap_pregsub@0x2e350 | 345 | 345 | MATCH |
| httpd/ap_get_server_built@0x2c510 | 4 | 4 | MATCH |

**10/10 MATCH**。重名条目的 external 段复测值=0,与修正后 targets 值一致(见下)。

## E. 发现的数据错误与修正(已执行,原子写)

### E.1 错误 1: 重名函数 skeleton 值被"最后一段"覆盖(44 处,已修)

- 根因: Lane S `gen_targets.py` 用 `compare_ghidra.py --func NAME` 测量;44 个重名名各输出**两段**(stub 杗 + external 块),解析器只保留最后一个 `[Skeleton]` 行 → 同名两条记录都被写成 external 块的值,stub 块真值丢失。
- 实例: `__ctype_b_loc` 两段 = `11 differ`(stub)/`identical`(external);修正前两条都记 11。
- 修正: `fix_targets_dup.py` import compare_ghidra 模块,以 Rugra 块地址为键逐块调用 `match_functions()+diff_function()`(与工具同一代码路径),44 处 external 块记录 `skeleton: {11|9|5|4|2} → 0`(Rugra 与 golden 的 external 构件块完全一致,真值即 0);defects/numbering 0 处需修;httpd 0 处需修;curl 排名按同排序键重排(top 区不受影响: rank1-16 顺序不变)。
- 原版备份: `targets.json.lane-s-orig`。

### E.2 错误 2: batch_driver.py 对重名的三处消费缺陷(已同步修,/dev/shm 内产物)

1. 断点续跑/记录 key `corpus/func_name` 对 44 对重名冲突(第二条被第一条记录遮蔽)→ key 改用 `target_id`(重名形如 `curl/free@0x22f0`;旧 targets 无 target_id 时回退原名);
2. artifact 文件名 stem 同名互相覆盖 → 重名条目 stem 追加地址(`curl__free__22f0.rust.txt`);
3. `extract_function_block` 按名取块有歧义 → 新增 addr 优先匹配。
- 回归: `py_compile` PASS;dry-run top-3 curl(3/3 pending,退出 0,报告生成);`--funcs __ctype_b_loc free` 正确选出 4 条消歧记录。

### E.3 targets.json 新增字段

- `target_id`: 全局唯一键(重名含地址);`name_dup`: 仅 44 对重名为 true;`block_class`: `plt_stub|external_import|init_plt_chunk|null`;`audit_fix`: 修正溯源块。

### E.4 driver 适配 repo 现存接口(Lane T,审计期间发现 repo 状态变化)

审计时发现 repo 已交付消费端(Gate 2-E commit `006db61`):`tools/run_stage_bisect.sh` 存在且 CLI 为 **`<oracle.proj> <rugra.proj>`**(两投影文件),非 Lane S 假设的 `<corpus> <addr> <name>` 三参数。已同步适配 batch_driver.py:

- (c) bisect 阶段改调 `run_stage_bisect.sh <oracle.proj> <rust.proj>`,解析 `kind:` 行;exit 0=MATCH、1=分歧(定位成功,不算失败)、2=FormatError(实测 V1_META_MISMATCH 样本与 nested MATCH 样本验证解析路径);
- (a)/(b) 产物改为 `<stem>.{oracle,rust}.proj`;rust 输出后检从"函数块数"改为"stdout 以 `META` 开头"(投影感知);
- 首分歧来源改为权威的 bisect 报告 kind(旧的文本 diff 保留为死代码,不再参与)。

## F. 审计后最终状态(总账闭环)

- 修正后 targets.json 逐块求和: curl Σskeleton = **3711** = `--summary-only` 全量真值(修正前 Lane S 版 Σ=4029,虚增 318,即 44 处 external 块被误记为 stub 值之和);httpd Σ = **3576** = 真值。**153 条逐块值与工具全量汇总完全自洽。**
- entry_addr: nm/readelf 复核零错误;rank 基于修正值重排(curl rank1-16 顺序不变,external 重名块跌至尾部)。
- targets.json: 153 条,新增 `target_id`/`name_dup`/`block_class`/`audit_fix` 字段;原版备份 `targets.json.lane-s-orig`。
