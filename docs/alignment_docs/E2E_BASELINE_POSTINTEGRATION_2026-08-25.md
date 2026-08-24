# A17 — Fresh E2E 基线（集成后）：master 8b2205a

任务 ID：`E2E-BASELINE-POSTINTEGRATION-0001`
日期：2026-08-24（Asia/Shanghai 深夜批）

## 0. 指纹

| 项 | 值 |
|---|---|
| Rugra HEAD | `8b2205a436b316510a73ba89b383c59f5cc981bd`（master，工作树干净） |
| 输入二进制 | `examples/curl`，SHA-256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`，161728 B |
| golden | `tests/golden/ghidra_curl_1204.c`（锁定 oracle Ghidra 12.0.4 `e40ed130…`） |
| 旧基线对照 | `f7b3c31`（THREE_FUNCTION_HANDOVER_2026-08-24.md §1） |
| 本 wave 集成的 src 变更 | ACTIONPOOL（`action.rs`，`bd8e38e`+`cad41c2`）、D1（`typeop.rs`，`e3e0053`）、jt-thunk（`jumptable.rs`，`054935f`/`e6a1393`/`8e09e59`）、fspec slice1（`space.rs`+`address.rs`，`d75f1bb`） |

## 1. 构建

命令（严格 flock + 专属 home 目录，staging 不落 /tmp）：

```
/usr/bin/flock /tmp/rugra-cargo-build.lock env CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/home/wirs/.cache/a17-baseline-target \
  TMPDIR=/home/wirs/.cache/a17-baseline-tmp \
  cargo build --locked --release --example curl_decompile
```

- **退出码 0**，`Finished release profile in 3m 03s`（237 条既有 warning，无 error）
- example 二进制 SHA-256：`b57c2f8f7ae8ccb6e06bee70f6221c73e75a1c86530b42fae75713fb36b8ab06`

### 队列事件（协调者已批准的处置）

构建启动后在 flock 队列等待约 47 分钟。原因：其他 agent 的 a13-strmgr 任务
（`cargo test --lib stringmanage`，worktree `/home/wirs/.cache/rugra-wt-stringmanage-core`）
测试二进制 `rugra-5a1ac04b0`（PID 1458336）**死锁**——5 线程全部 `futex_do_wait`、
43+ 分钟 0 CPU、无子进程，不可能自行恢复，并阻塞队列中 15 个任务。
经协调者批准后 `SIGKILL 1458336/1457804/1450960` 释放队列，随后本构建 3m03s 完成。
**后续行动项**：stringmanage 任务 agent 会收到测试失败，需排查该 fixture 死锁根因。

## 2. 单次运行

- 从仓库根目录运行（example 以相对路径 `examples/curl` 读输入）；首次误从 artifacts
  目录运行仅得 62 B（`Could not read examples/curl`），已废弃重跑。
- **run 退出码 0**；stdout/stderr 严格分离；stderr 0 panic/abort，正常收尾于
  `[STEP] _fini print done`。

| 产物 | 大小 | SHA-256 |
|---|---:|---|
| C 输出 `curl.stdout.c` | 69,667 B | `fc9a33baaab1310929b78b508b27f6810fd5e2eca7da80bf17d2a584e91d60e7` |
| stderr `curl.stderr.log` | 241,899 B | `c5f3f93c57c5d883ed0d5ec420b73c01a9f6e65979e3663f1272d8ad2ca1a572` |

归档目录：`/home/wirs/.cache/a17-baseline-artifacts/`（含 build.log、build/run 退出码文件）。

## 3. 差分结果（vs `tests/golden/ghidra_curl_1204.c`）

全局（`--summary-only`）：

| 指标 | 本次（8b2205a） | 旧基线（f7b3c31） | Δ |
|---|---:|---:|---:|
| 匹配函数 | 123/124 | 123/124 | 0 |
| Total skeleton diff lines | **2409** | 2409 | **0** |
| Total defects | **2**（2/123 函数） | 2 | **0** |
| Total numbering issues | **1** | 1 | **0** |

三函数（`--func <f> -v`，函数级口径）：

| 函数 | skeleton diff（新） | skeleton diff（旧） | 形态变化 | defects | numbering |
|---|---:|---:|---|---:|---:|
| `hugehelp` | **18** | 18 | 无（仍是 6×`puts(LIT /* LIT */)` + return） | 0 | OK |
| `progressbarinit` | **20** | 20 | 无（`*bar=LIT`、`bar->prev=LIT`、`extraout_RAX`、7 层嵌套 `->total` 均原样） | 0 | OK |
| `my_fwrite` | **16** | 16 | 无（双 `V` 声明、空 if 体、直落 `fwrite`+`return` 均原样） | 0 | OK |

## 4. 新旧对比结论：C 输出逐字节一致

**新基线 C 输出 SHA-256 = 旧基线 C 输出 SHA-256 = `fc9a33ba…d60e7`。**
即 master 自 `f7b3c31` 集成的四个 src 变更（ACTIONPOOL/D1/jt-thunk/fspec slice1）
对 curl 全量反编译的 C 文本**零字节影响**。所有 compare 指标（全局与函数级）
随之完全一致。这是比逐指标对比更强的证据：输出分布整体未移动。

stderr SHA 不同（`9ed73fe7…` → `c5f3f93c…`），属日志噪音差异（`[ACTION]/[STEP]`
等诊断 TAG 的时间戳/顺序），stdout C 输出已分离、不受污染。

### 逐项归因（为何四个集成零 E2E 影响）

1. **ACTIONPOOL（`bd8e38e`+`cad41c2`，action.rs）**：从注册 base 克隆 filtered Action
   池属于基础设施重构，池内容与派发顺序保持等价，Action 执行序列不变 → 输出不变。
   与"行为等价重构"的预期一致。E2E 零变化是该重构未引入派发回归的正面证据。
2. **D1（`e3e0053`，typeop.rs）**：仅落地 `TypeOpCall::getInputLocal` 的 callspec
   input typing 入口。按交接文档 §3.1/§5，CALL input 走 local dispatch 需要其调用方
   D2（`ActionInferTypes::build_localtypes` 播种 CALL inputs）**尚未实现**——
   入口无人调用，自然零影响。**符合任务预期（"D2 未做，CALL input 播种预期无 E2E 影响"）**。
3. **jt-thunk（`054935f`/`e6a1393`/`8e09e59`，jumptable.rs）**：修复针对特定
   jump-table thunk 恢复错误分类与边缘证据；curl 语料未触发改变行为的 thunk 形态
   （或恢复结果与此前相同），故零变化。该修复的收益需在含相应 thunk 形态的语料上验证。
4. **fspec slice1（`d75f1bb`，space.rs+address.rs）**：fspec space identity 为
   identity 地基（slice1），尚未接入会改变输出选择的生产路径 → 无 E2E 影响，符合
   slice 分期预期。

## 5. 回归警示

**无回归。** 三函数 skeleton diff（18/20/16）、函数体形态、全局
skeleton 2409 / defects 2 / numbering 1 全部与 f7b3c31 基线逐项相同；
且 C 输出整体逐字节一致，不存在任何"某函数变差"的对照项。

遗留（均为旧基线已登记项，非本次回归）：
- 全局 defects=2、numbering=1 仍开放（绑定既有 TODO）；
- `hugehelp` 字符串常量（`&DAT_*`/字符串折叠）等根因仍在 THREE_FUNCTION_HANDOVER §3 清单中，
  本 wave 集成均未触及这些路径（D2 未做、StringManager/ConstantPtr 波未启动）。

## 6. 回流与产物

- 回流：`cp curl.stdout.c /home/wirs/DEV/Rugra/result/curl_cur.c`（gitignored，已核对 sha 一致）。
- 产物根：`/home/wirs/.cache/a17-baseline-artifacts/`
  （`curl.stdout.c`、`curl.stderr.log`、`build.log`、`build_exit_code.txt`、`run_exit_code.txt`）
- 构建缓存：`/home/wirs/.cache/a17-baseline-target/`（保留供复用）
