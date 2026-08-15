# 辅助脚本工具库 (Tools & Scripts)

此处归档所有用于项目测试辅助、Ghidra API 挂钩导出、一致性检测对拍的各种外部脚本（如 Python、Shell 脚本等）。不要将它们零散地扔在 Rust 项目根目录下。

目前主要脚本有：
- `ffi_test.py`: 涉及通过 C++ FFI 联调的一些绑定与驱动测试段。
- `ghidra_export.py`: 挂载在 Ghidra 原生环境中执行，用于将其内部的 P-code 数据导出为我们可以对比的形式。
- `pcode_compare_test.py`: 自动比较我们的 P-code 生成串与 Ghidra 原生串的微小差异脚本。

## 可复现快速构建

`rugra_build.py` 是 Cargo 的受控入口。它默认使用 `--locked --offline`、
固定 locale/timezone、记录工具链和输入指纹，并使用全部可用 CPU。若系统安装了
`sccache`，脚本同时缓存 Rust 与 C/C++；只有 `ccache` 时仅缓存 C/C++；两者都没有时
安全回退到直接编译。`cc` build dependency 的 `parallel` feature 会让 22 个 SLEIGH
翻译单元遵守 Cargo jobserver 并行构建。

```bash
# 日常快速语义检查（默认 fast-release）
python3 tools/rugra_build.py check --all-targets --report /tmp/rugra-build.json

# 快速可运行产物
python3 tools/rugra_build.py build --all-targets

# 最终发布构建仍使用原来的 fat-LTO release profile
python3 tools/rugra_build.py build --profile release

# 查看将执行的受控命令和环境，不启动编译
python3 tools/rugra_build.py check --dry-run
```

`fast-release` 只用于反馈速度；它不替代最终 `release` 门禁，也不改变锁定 oracle
或行为证据的判定标准。

## Changed-function fixture 选择

`select_fixtures.py` 使用生成式 `FUNCTION_LEDGER.json` 的 Rust 函数 span 和稳定 ID，
把 git diff 映射到 `tests/oracle/fixture_registry.json`。删除、顶层改动或没有已登记
fixture 的 `src/*.rs` 改动会 fail-closed：选择全部 fixture，并在 `--strict` 下返回 2，
不会用“没选中测试”冒充无影响。

```bash
# 当前工作树，机器可读结果
python3 tools/select_fixtures.py --pretty

# 提交前只看暂存区；未覆盖源码改动直接失败
python3 tools/select_fixtures.py --staged --strict --pretty

# 显式函数或路径诊断
python3 tools/select_fixtures.py --function RG-F-9f9b178c52fe97265fbe --pretty
python3 tools/select_fixtures.py --path src/sleigh_ffi.rs --pretty
```

## 四级门禁

`rugra_gate.py` 把相同事实源组合成四个延迟层级，并为每条命令记录输入 hash、
工具输出 hash、耗时、timeout 和 exit 状态：

| 层级 | 目标 | 主要内容 |
|---|---|---|
| `edit` | 秒级反馈 | 门禁健康、changed annotation/ref、fast library check |
| `commit` | 原子提交 | 全静态门禁、生成账本、fast all-targets、受影响 fixture |
| `wave` | 集成 wave | commit + 全测试 + 全 fixture + curl/httpd/语法/诊断 golden |
| `nightly` | 冷闭包 | wave + fresh-target canonical release 全目标构建 |

```bash
python3 tools/rugra_gate.py edit --report /tmp/rugra-edit-gate.json
python3 tools/rugra_gate.py commit --staged --report /tmp/rugra-commit-gate.json
python3 tools/rugra_gate.py wave --report /tmp/rugra-wave-gate.json
python3 tools/rugra_gate.py nightly --report /tmp/rugra-nightly-gate.json

# 只查看命令和 fixture 选择，不执行
python3 tools/rugra_gate.py commit --staged --dry-run
```

`commit` 以上层级遇到 fixture coverage gap 会在运行前返回 2。`wave`/`nightly`
固定运行 registry 中的全部 fixture；旧 11.3.2 golden 只保留 diagnostic 身份。fixture
默认通过内容寻址缓存运行；`--no-cache` 强制直跑，`--refresh-fixtures` 重新执行并验证
相同 provenance 不会产生不同结果。

## Oracle 内容寻址缓存

`oracle_cache.py` 保存昂贵 oracle runner 的 stdout/stderr、阶段 manifest 或其他产物。
键不是“测试名”，而是锁定 oracle commit、architecture、compiler spec、analysis
options、输入、工具、comparand、命令和显式环境的规范化 provenance hash。每次命中仍会
重算这些输入并逐文件校验缓存内容；损坏或 provenance 漂移会 fail-closed。

capture 的子进程环境与 provenance 环境完全一致（2026-08-15，
`ORACLE-CACHE-HARDEN-0002`）：`Popen(env=...)` 只包含已声明变量
（`DEFAULT_ENV_KEYS` + 执行必需的 `EXEC_ENV_KEYS` + `--env`），未声明环境变量对命令
不可见；argv0 按子进程 PATH 解析，PATH 值或 PATH 目录内容变化会更换 key。命令执行后
重读环境与 provenance，漂移即拒绝入库；restore 恢复后逐 artifact 交叉校验
hash/size/结构并重新校验缓存源，任何缺失、多余或篡改均 fail-closed。

```bash
# 查看键
python3 tools/oracle_cache.py key \
  --metadata tests/oracle/decompress_1204.metadata.json \
  --input fixture=tests/oracle/decompress_1204.cc \
  --tool runner=tools/run_decompress_oracle.sh \
  --comparand rust=src/compression.rs

# 缓存并重放成功 runner；失败结果不会进入缓存
python3 tools/oracle_cache.py capture \
  --metadata tests/oracle/decompress_1204.metadata.json \
  --input fixture=tests/oracle/decompress_1204.cc \
  --tool runner=tools/run_decompress_oracle.sh \
  --comparand rust=src/compression.rs \
  -- tools/run_decompress_oracle.sh
```

默认缓存位于 `.rugra-cache/oracle/`，不进入 Git。`store`/`verify`/`restore` 可用于
阶段快照；restore 目标必须不存在，恢复文件为只读，避免把缓存对象当工作副本修改。

## Pipeline stage 首差异

`stage_diff.py` 将提升、SSA、结构化、打印等阶段的**原始** artifact 依序写入 manifest，
随后定位两侧第一个 provenance、stage ID、顺序、schema、state、内容 hash 或缺失差异。
工具不重排 JSON、不消除别名、不规范化 CFG，因此不会为了让 diff 变小而丢掉决定性语义。

```bash
python3 tools/stage_diff.py snapshot \
  --metadata tests/oracle/sleigh_decode_1204.metadata.json \
  --producer rugra --stage lift=/tmp/rugra-lift.json --stage ssa=/tmp/rugra-ssa.json \
  --output /tmp/rugra-stages.json

python3 tools/stage_diff.py compare /tmp/ghidra-stages.json /tmp/rugra-stages.json --pretty
```

`compare` 返回 0 表示所有阶段原始 hash 相同，1 表示找到差异，2 表示 manifest/provenance
无效。stage manifest 也可作为 `oracle_cache.py store` 的只读 artifact 保存。

## 失败输入最小化

`reduce_fixture.py` 对仍能复现 oracle mismatch 的输入做 deterministic `ddmin`，支持
顶层 JSON list、JSON Pointer 指向的对象字段 list，以及 hex byte stream。predicate 用 argv
直接启动，必须含独立的 `{input}` 占位符；不经过 shell。默认 exit 1=interesting、exit
0=boring，其他 exit/timeout/重复运行不一致均 fail-closed。

```bash
python3 tools/reduce_fixture.py \
  --input /tmp/failing.json --output /tmp/min.json --trace /tmp/min.trace.json \
  --format json-field --field /functions/0/ops \
  -- python3 tools/my_mismatch_predicate.py '{input}'
```

候选按内容 hash 在单次 reduction 内 memoize；最终会重新验证 predicate，并逐个尝试删除
剩余 unit 证明 1-minimal。输出 trace 保留原始/最小输入指纹、完整 argv/可执行文件 hash、
受控构建环境、所有 predicate 结果、超时与重试参数；额外必需环境变量用 `--env NAME`
显式加入。这样最小 case 可连同完整证据升格为正式 oracle fixture。

### Schema 2 合同（2026-08-15，`DIFF-REDUCE-HARDEN-0002`）

seed 先对**原始文件 bytes** fresh 执行（绕过 memo），并检测 render normalization drift
（原始与 re-rendered seed 双指纹入 trace；若 drift 改变 `predicate_signature` 则
fail-closed，渲染层不得掩盖真实差异）。predicate 每次执行四分型：
`INTERESTING(predicate_signature)` / `BORING` / `INVALID`（`--invalid-exit`，默认 3，
只跳过当前 candidate；interesting 但签名≠seed 也记 `INVALID(signature_mismatch)`，
bug A 不会缩到 bug B）/ `HARNESS_ERROR`（fail-closed）。签名取自 stdout JSON（整体或
末行）的 `predicate_signature` 键，规范为 sorted-compact JSON 字符串，跨进程可比。
谓词不输出签名时为兼容模式（`signature_enforced=false`），bug 漂移防护依赖谓词履约
输出稳定签名。最终验证绕过 memo 按 `--retries` 次对最小 case fresh 重跑并要求
签名==seed，防缓存假阳性。执行记录 fsync 追加到 `<trace>.eval.jsonl`（成功后删除），
中断后 `--resume <log|trace.json>` 在谓词身份（argv/exit/timeout/retries/可执行文件
sha256/环境/输入指纹）逐字段匹配后热启动 memo 续跑；schema 1 旧 trace fail-closed 拒绝。

## Oracle fixture registry 治理（2026-08-15，`ORACLE-REGISTRY-0001`）

`oracle_registry.py`（零依赖）提供 registry 目标契约与迁移工具链：

- `tests/oracle/schema/fixture-v1.schema.json`：registry 条目目标契约——`schema`
  const、40-hex `oracle_commit`、fixture 必填 `impact.{rust,ghidra}_function_ids`
  （`RG-F-/GH12-F-` 20-hex pattern，显式拒绝 ordinal/placeholder）、`evidence_status`
  限定 B2 状态机、全路径 repo-relative。
- `doctor`：反向发现磁盘全部 metadata/runner/comparand 并与 registry 交叉核对；
  orphan、重复 ID、缺 provenance、状态冲突、stale/rekey-gap/unmappable function ID
  全部 fail-closed（rc 0/1/2），输出 repo-relative、排序、无时间戳。
- `schema`：内置 draft-07 子集校验器（不依赖 jsonschema）。
- `lint [--strict]`：doctor + schema 合并检查（前向兼容 ENFORCE-0001）。
- `plan [--check-determinism]`：生成确定性迁移计划——replacements 按
  (file:line:column) 断言式替换，manual_reselect/unmappable 禁止文本替换须按账本
  重选；计划头部带 registry/ledger/migration 三文件 sha256 指纹，应用前须重生成；
  collateral_pins 列出 runner 编辑后须同 commit 重钉的 `comparand.runner_sha256`。

当前基线：doctor 报 163 issue / 13 类码（迁移执行见 `ORACLE-METADATA-MIGRATE-0001`）。
