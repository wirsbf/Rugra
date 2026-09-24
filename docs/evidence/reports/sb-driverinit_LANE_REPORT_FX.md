# LANE REPORT FX/FX3 — HTTPD-DRIVER-ARCH-INIT-0001 (wt/driverinit)

- **Branch**: `wt/driverinit`, base = 9458a61b (亲父), head = **de813719** `fix: install arch init trio in single-function driver (HTTPD-DRIVER-ARCH-INIT-0001)`
- **Owner**: sb-driverinit (fixer-FX → fixer-FX3 续跑收口,两次中断后接手)
- **TODO**: HTTPD-DRIVER-ARCH-INIT-0001 → **DONE**(docs/TODO_BOARD.md 同 commit 更新;新登记 residual 行 HTTPD-FULLEMPTY-ELSE-0001 residual 待派)
- **Write-set**: `examples/rugra_decompile_func.rs`(add-only 33 行)+`docs/TODO_BOARD.md`;`examples/httpd_decompile.rs` 零改动;src/ 零改动。

## 三件状态(核对结论)

| 件 | httpd 驱动 | 单函数驱动(rugra_decompile_func.rs) | 本 lane |
|---|---|---|---|
| `archid="x86:LE:64:default"` | 已在位(httpd_decompile.rs:332,ES/fb935792) | **补齐**(commit de813719) | ✅ |
| `set_register_xref`(SleighCtx 枚举) | 已在位(:333) | **补齐** | ✅ |
| `set_commentdb`(CommentDatabaseInternal) | 已在位(:334-336) | **补齐** | ✅ |

核对方法:curl vs httpd init 链十项 diff(SLEIGH 目录/register_xref/pspec/cspec/archid/xref/commentdb/TypeFactory+data_org+setup_sizes/PcodeInjectLibrary+UserOp/parse_compiler_config)。httpd 三件自 ES(fb935792,HTTPD-CSPEC-ARCH-0001)在位,语义=curl 同源(同 SleighCtx 枚举同 tuple 序;commentdb 单库 Arc=oracle 单 Architecture 语义)。残余缺口仅单函数驱动(EO2 时代只挂 set_types),本 lane 补齐,照 curl_decompile.rs:1877-1900 同款。

## 输出影响(A/B 三探针 my_fwrite/ap_ht_time/ap_log_rerror,其余行零变化)

1. 警告通道:stderr `[WARNING]` → commentdb → stdout `/* WARNING: Unknown calling convention */` 头注释(printc.cc:2650 setupFunctionList=oracle 通道;消息体=coreaction.cc:4903 modelless 无锁形态)。
2. 寄存器名渲染:`in_register_00000008→in_ECX`、`…10→in_RDX`、`…20→in_RSP`、`…110→in_FS_OFFSET`(sleighbase.cc:144-168 get_register_name,B3-VARMAP-REGNAME-0001 curl 同款效果;golden 零 `in_register_` 泄漏)。

## 三门禁(门禁二进制=亲父 9458a61b 树构建;门禁面源码零改动,数字即亲父基线)

| 门禁 | 数字 | 状态 |
|---|---|---|
| curl E2E vs ghidra_curl_1204 | **2145 / 0 defects / 0 numbering**(124 函数) | ✅ 复核 |
| httpd 门禁面 29/29 vs ghidra_httpd_1204 | **2057 / 0 / 0** | ✅ 复核 |
| httpd 全量 MAX_FUNCS=840 vs direct-runner | **38672 / 1 / 0**(470 函数;panic=0 TIMEOUT=0 not-settling=0) | ✅ 复核(残 1=ap_get_server_name 空 else L21=亲父预存→新登记 residual 行) |
| 三投影 next_url / match_url / parseconfig.constprop.0 | **MATCH×3**(335/96457、340/80385、335/130099,stage+snapshot identical) | ✅ 复核 |

FX3 补验(接手后):盘上二进制 no-op 重建确认=on-disk 源码所建;三探针复跑 .c 输出与 after 工件逐字节相同;三门禁 compare 与三投影 stage_bisect 逐一重跑,数字与 FX 亲测一致。

## 证据

- 工件: /dev/shm/rugra-tests/sb-driverinit/(after/ 三门禁输出+三投影;base_/after_examples_* A/B 探针;run_gates.sh)
- Commit message 全文: 本目录 commitmsg.txt(含 ## Alignment Evidence 四类语义 + ## Differential)
- 复核工件(回收前存档): repro_fx3/(三探针 .c 与 after 逐字节相同)

## 回收

- `/dev/shm/rugra-targets/sb-driverinit`(1.7G)已删除。
- `/dev/shm/rugra-tests/sb-driverinit/repro_fx3`(FX3 复跑副本)已删除;主证据目录保留(TODO 行引用)。
- worktree `/dev/shm/rugra-worktrees/driverinit` 保留待 root 集成 merge。
