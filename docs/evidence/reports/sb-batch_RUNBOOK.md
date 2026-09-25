# RUNBOOK — Phase 2 stage-bisect 集成手册 (Lane T, 2026-09-22)

> root 视角的集成顺序、接口验收与风险处置。批驱动 = `/dev/shm/rugra-tests/sb-batch/batch_driver.py`
> (Lane S 交付,Lane T 已适配本手册 §1 的 repo 真实接口),目标清单 = 同目录 `targets.json`
> (153 条,Lane T 审计修正版:逐块 skeleton、`target_id`/`block_class` 字段,见 `AUDIT.md`)。

## 0. 现状快照(集成前提核对)

| 组件 | 状态 | 位置 |
|---|---|---|
| 投影格式契约 v1.1→v1.2.1 | ✅ repo 已锁定(枚举域 erratum 已入 spec) | `docs/alignment_docs/STAGE_BISECT_SPEC_1204.md` |
| 消费端 bisect(v1.2.1) | ✅ **已集成 master**(commit `9d8b0cf`+`e561762`:枚举域 OPCODE_RE + 74 名表 + s/f/o 描述符) | `tools/stage_bisect.py` + `tools/run_stage_bisect.sh` |
| oracle harness 骨架 | ✅ repo 已有骨架 | `tools/stage_bisect_projection.cc`(`stage_bisect.py --emit-harness` 可再生) |
| oracle 投影 runner(Lane A) | ✅ **枚举域投影就绪**(wt/sb-oracle `614b646` 系列;next_url 投影已重产,META 规范化、producer=8776a327) | `sb-oracle/next_url.oracle.projection`(355 stages/101,892 ops) |
| Rust 投影 emitter(Lane C) | 🔶 emitter 已交付(05c8314)、**C 对齐 punch list 就绪待执行**(8 项,见 `sb-integration/REMAINING_DELTA.md` §2) | wt/sb-rust `examples/curl_decompile.rs` stage_vn/stage_snapshot/emit_stage_projection |
| 批归因驱动 + targets | ✅ 本目录 | `batch_driver.py` / `targets.json` |

## 1. 接口契约(Lane A / Lane C 交付物验收标准)

### 1.1 oracle 投影 runner(Lane A 交付 `tools/run_stage_projection_oracle.sh`)

```bash
bash tools/run_stage_projection_oracle.sh <corpus> <entry_addr> <func_name>
# corpus     ∈ {curl, httpd}
# entry_addr = targets.json 权威地址(0x…;nm/readelf 复核版,Lane T AUDIT §C)
# func_name  = targets.json func_name(保留 GCC 后缀,如 getparameter.constprop.0)
```

- **stdout = v1.1 投影文本**(首行 `META side=oracle …`),stderr = 诊断,退出 0;
- META 身份键必须与 emitter 完全一致(任一不等 → 消费端 `V1_META_MISMATCH` exit 1):
  `oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b`、`arch`、`cspec`、
  `analysis_options`、`build_flags=v1-no-OPACTION_DEBUG`、
  `binary_sha256=<sha256(examples/<corpus>)>`、`func_entry=<entry_addr>`、
  `load_mode=single_function_bfd`、`maxrestarts=1`;
- `func_name`/`producer` 两侧异构属 warning 级(不进身份键);`unique_base` 先比基址(warning 金丝雀)。

### 1.2 Rust 投影 emitter(Lane C 交付,examples 级)

```bash
RUGRA_STAGE_FUNC=0x<addr> target/release/examples/<corpus>_decompile
```

- **stdout = v1.1 投影文本**(首行 `META side=rugra …`),`producer=<rugra-tree-commit>`;
- env 未实现/被忽略时输出 C 函数块文本 → driver 自动判 `pending env_ignored`(**不允许假 ok**);
- src/ 侧仅允许纯只读访问器(`// RUGRA-GLUE:` 注释,spec §构建与边界);
- **加载契约必须对齐 oracle 的单函数 BFD 契约**(同入口/同 context/同原型与选项注入),
  不得沿用全程序 shim 路径直接开跑 —— `load_mode` 在身份键里,不同值直接 `V1_META_MISMATCH`。

### 1.3 bisect(repo 已定案,消费端)

```bash
bash tools/run_stage_bisect.sh <oracle.proj> <rugra.proj>
```

- exit `0` = MATCH;`1` = 已定位分歧(人类报告含 `kind: <KIND>` 行,含 `V1_META_MISMATCH`);`2` = FormatError(投影文法错,stderr `error: …`);
- 机器可读:`python3 tools/stage_bisect.py --json --v1 <left> <right>`(wrapper 不带 --json);
- 自检:`python3 tools/stage_bisect.py --selftest`(27 场景)。

driver 已按 1.1/1.2/1.3 接线:oracle/rust stdout 各存 `artifacts/<stem>.{oracle,rust}.proj`,
双侧 .proj 落盘后自动调 `run_stage_bisect.sh`,解析 `kind:` 行写入 `attribution_report.md`。

## 2. 集成步骤(root 视角,每步含验收)

### Step 0 — merge wt/sb-bisect 消费端(前提,已基本落位)

> **状态 2026-09-22(Lane AG 核对)**:✅ 完成。消费端 v1.2.1 已集成 master
> (`9d8b0cf` 枚举域拼写+闭表+单射性,`e561762` s/f/o 描述符合链);实测双侧
> next_url 投影文法零 FormatError,off-table 拼写降级为 advisory(31,558 行,
> 全部 rugra 侧 quirk 四槽,见 REMAINING_DELTA §3)。selftest 照旧跑。

```bash
git merge wt/sb-bisect            # 若 006db61 尚未在目标分支
python3 tools/stage_bisect.py --selftest        # 预期: 27 scenarios 全绿, exit 0
bash tools/run_stage_bisect.sh \
  /dev/shm/rugra-tests/wt-sb-bisect/nested_oracle.proj \
  /dev/shm/rugra-tests/wt-sb-bisect/nested_rugra.proj
# 预期: kind: MATCH, exit 0(F-1 放宽后嵌套流合法性的消费端证据)
bash tools/run_stage_bisect.sh \
  /dev/shm/rugra-tests/wt-sb-bisect/meta_oracle.txt \
  /dev/shm/rugra-tests/wt-sb-bisect/meta_rugra_wrongsha.txt
# 预期: kind: V1_META_MISMATCH (binary_sha256), exit 1(身份键前置校验证据)
```

### Step 1 — Lane A 交付后:oracle 投影冒烟(`next_url`)

> **状态 2026-09-22(Lane AG 核对)**:✅ oracle 投影枚举域就绪。wt/sb-oracle
> `614b646` 系列重产 `sb-oracle/next_url.oracle.projection`:op-line 已切
> `get_opname(op->code())` 枚举域(38 distinct 全落 74 名表内),META 身份键
> 9 项规范化(arch=x86:LE:64:default/cspec=gcc/analysis_options=default)。
> 下述 batch_driver 冒烟步骤对全 corpus 仍待 Lane A runner 脚本化。

```bash
cd /dev/shm/rugra-tests/sb-batch
python3 batch_driver.py --targets targets.json --funcs next_url
# 预期: oracle=ok(0x4ff0 投影落盘 artifacts/curl__next_url.oracle.proj);
#       rust=pending(RUGRA_STAGE_FUNC 未实现或输出 C 文本);
#       bisect=pending(no projections / waiting oracle+rust);
#       退出 0,attribution_report.md 更新。
head -3 artifacts/curl__next_url.oracle.proj    # 预期: META side=oracle … 身份键齐全
```

### Step 2 — Lane C 交付后:双侧投影 + 首分歧

> **状态 2026-09-22(Lane AG 实跑)**:🔶 **C 对齐 punch list 就绪**(8 项
> P1-P8,`sb-integration/REMAINING_DELTA.md` §2,含现值/目标值/emitter 位置/验证方法);
> 当前实跑卡点分层(L1→L7):L1 META 三键(P1-P3)→ L2 op@universal:start op0
> = **D10 待裁决**(2534 PLT 行 + SeqNum time 恒漂 +47 + 尾部 4 op)→ L3
> s:ram/c:3:8(P5)→ L5 time 漂移(D10 同源,非 emitter)→ L7 @END activeparam
> **9 vs 2(新 D14,管线层)** + seq29 oppool1(**D9 待裁决**)。
> D9/D10 裁决在途,punch list 不预设其结论;P4/P6/P7/P8 虽非本语料序首卡点,
> 仍为硬不兼容域(31,558/12,492/12,944/2,840 槽位),须随 P1-P5 一并落地。

```bash
cargo build --release --example curl_decompile --example httpd_decompile   # C 侧交付后
cd /dev/shm/rugra-tests/sb-batch
python3 batch_driver.py --targets targets.json --funcs next_url
# 预期: oracle=ok + rust=ok → bisect 执行;
#       exit=0 kind=MATCH → 首分歧 identical;或 exit=1 kind=<KIND> → 归因成立;
#       artifacts/curl__next_url.bisect.txt 保存完整首分歧报告。
```

### Step 3 — 首分歧归因批跑(top-N 循环)

```bash
python3 batch_driver.py --targets targets.json --top 10 --corpus curl --timeout 600
# 断点续跑: 再执行同命令自动跳过 overall=attributed 的记录(targets_done.json);
# pending/failed 自动重试;单函数失败/超时不中断批次(退出恒 0)。
```

### Step 4 — F-1 放宽后的嵌套流验证(真实投影)

F-1(Gate 2-E attempt 2):`@RESTART` 只要无挂起 `@SNAP` 即合法,生产端可将根
RestartGroup 帧跨轮保持打开;嵌套交错流(子级先完成,规范 (iii))两侧必须同构,勿压扁。

```bash
# 4a. 消费端负例守卫(合并后一次性)
bash tools/run_stage_bisect.sh /dev/shm/rugra-tests/wt-sb-bisect/nullslot_{oracle,rugra}.proj   # MATCH
bash tools/run_stage_bisect.sh /dev/shm/rugra-tests/wt-sb-bisect/meta_oracle.txt /dev/shm/rugra-tests/wt-sb-bisect/seqgap.proj  # FormatError, exit 2
# 4b. 真实函数含 restart 的投影(main 几乎必触发 universal restart):
python3 batch_driver.py --targets targets.json --funcs main
# 预期: bisect 不因跨轮根帧报 FormatError;若报 → 生产端违反 F-1 同构,回 Lane A/C。
```

## 3. 风险清单(高发故障与处置)

| # | 风险 | 触发形态 | 处置 |
|---|---|---|---|
| R1 | **V1_META_MISMATCH: binary_sha256 / func_entry** | curl 与 httpd 投影互比、或重名/错地址目标 | 严格按 targets.json 的 corpus+entry_addr 取目标;身份键 9 项逐项核对(`--json` 输出 meta 段) |
| R2 | **external_import 块不可投影** | 48 条 `block_class=external_import`(0x19000–0x19178)在 ELF 无实体,oracle BFD 单函数加载必失败 | Phase 2 首批**排除**该类(选 `block_class ∈ {null, plt_stub}` 或 top rank 真实函数);AUDIT §C.2 已给加固 lane 情报 |
| R3 | **V1_META_MISMATCH: load_mode** | Rugra 沿用全程序 shim 而非单函数 BFD 契约 | Lane C 必须实现与 oracle 同入口/同 context/同注入的加载路径(spec §构建与边界) |
| R4 | **FormatError exit 2: 文法类** | seq 缺口/复用(R-2)、@SNAP 不紧跟 @END、EOF 栈未闭合、@END 属性集错、per-slot `-` 拼写(M1/R-1)、杂散 op 行、@RESTART 位置错 | 定位到生产端枚举 bug;selftest 内置 battery 复现这些路径;手头样本 seqgap.proj 即负例 |
| R5 | **嵌套流压扁** | 生产端把规范 (iii) 交错流压成先序 → 两侧 stages 完成序不同构 → 首分歧错位(可能假 MATCH/假分歧) | 生产端如实产出;消费端 B-1 栈式解析 + 完成序比较已覆盖,Step 4 验证 |
| R6 | **unique offset 漂移被抹除** | 有人用 `--relax-unique` 把金丝雀当对齐证据 | `--relax-unique` 仅 triage;归档报告必须用无 relax 的输出 |
| R7 | **emitter 假 ok** | `RUGRA_STAGE_FUNC` 被忽略仍输出全语料 C 文本 | driver 后检 stdout 必须以 `META` 开头,否则 pending env_ignored(Lane T 已实测该路径) |
| R8 | **重名目标混淆** | 44 对重名(plt_stub/external 两块)key/artifact 冲突 | targets 已消歧 `target_id`(`curl/free@0x22f0`),driver key/stem/块提取均已按地址(Lane T 修正) |
| R9 | **httpd 侧预算不等价** | Rugra worker 15s vs oracle 每函数 30s;`main` 3062B、`ap_fini_vhost_config` 1615B 均在 8192B 截断限内 | 归因批跑 httpd 时 `--timeout ≥ 60`;超时记录 timeout 状态自动重试,不当中断 |
| R10 | **双侧 build flag 漂移** | 任一侧带 OPACTION_DEBUG 构建 | 身份键 `build_flags=v1-no-OPACTION_DEBUG` 双侧统一;交付物 build 命令进 provenance |

## 4. driver 速查

```bash
python3 batch_driver.py --targets targets.json [--top N] [--corpus curl|httpd|all]
                           [--funcs NAME…] [--timeout S] [--dry-run] [--force]
# env: RUGRA_BATCH_TIMEOUT(默认 300s);--dry-run 全 pending、不写 targets_done.json
# 产物: attribution_report.md / targets_done.json / PROGRESS.txt / artifacts/*.{oracle,rust}.proj|.bisect.txt
```
