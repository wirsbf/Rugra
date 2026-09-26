# SLEIGH Phase2 换装报告 — Rust 运行时（kuna-sleigh）替换 C++ FFI 链（2026-09-26，Lane SLEIGHP2）

> 车道 `wt/sleighp2`（worktree `/dev/shm/rugra-worktrees/sleighp2`），基 = master `d4347dcd`，
> ghidra/ symlink = 锁定 oracle `e40ed13014025f82488b1f8f7bca566894ac376b`（HEAD 亲验）。
> 票：`SLEIGH-RUSTIFY-PHASE2-0001`。前置：Phase0 裁决（BORROW-TRACK）+
> Phase1（四 crate vendor + 146/146 sweep + slacomp 生产切换，C++ 编译器退役）。
> 本票任务 = 把**解码运行时**也 Rust 化：vendored `kuna-sleigh`（32,687 行，Phase1
> 已入仓）换装 build.rs 编译的 21 文件 C++ 运行时 + `sleigh_shim` C ABI + FFI 链。

## 0. 结论速览

| 门禁 | 结果 |
|---|---|
| **① op-for-op 恒等**（双引擎单进程逐指令差分） | **PASS**：36 面 698,605 decodes（640,788 ok + 57,817 err），5,550,599 个 p-code op 逐项对比（step + 全 op 字段含 identity/space_ref + 错误 kind/instruction_length/**message 字节**），`decode_divergences=0 catalog_divergences=0`（fast-release 与 release 双轮复跑同判） |
| **② E2E 字节恒等**（五语料 A/B） | **PASS**：curl 95,842B / httpd 56,219B / vsh 49,584B / sq 2,416,424B / sqlite3 233,520B 全部 `cmp` 零差（§3）；`cargo test --lib` 1777P/0F 双引擎恒等 + bank 391/391 + 三门禁绿 |
| **③ 性能**（decode 吞吐） | 同量级 ±20%（口径摆动）；E2E 墙钟 curl canon：cpp 146.6s vs **rust 130.6s（Rust −11%）**（§3b） |
| **④ C++ 退役** | 门禁全过后执行（build.rs 21 .cc 编译删 + sleigh_shim/ 删 + cpp_backend 删；sweep 工具 sleigh_opt oracle 参照仪器保留） |

## 1. 换装架构（commit `64434f38`）

`src/sleigh_ffi.rs` 重构为引擎枚举，公开面（`SleighCtx::{new, with_engine,
try_set_image, try_set_context, load_pspec, one_instruction, decode,
instruction_length, num_spaces, space_info, num_registers, register_info}`）
不变，`SleighLifter`/`debugproto`/examples 零改动：

- **Cpp 后端**（`#[cfg(has_sleigh)]`）：原 FFI 路径整体移入 `cpp_backend`
  模块，行为逐字节不变。
- **Rust 后端**（`rust_backend` 模块）：`kuna_sleigh::sleigh::Sleigh` 引擎
  （`Sleigh::new(SharedLoadImage, ContextInternal)` + `initialize_from_sla`），
  `RustSleighEngine`/`RustPcodeCollector` 逐条镜像 shim 语义。
- **选择开关**：`RUGRA_SLEIGH_ENGINE=cpp|rust`（运行时 env）；`build.rs`
  的 C++ 编译位于 `RUGRA_SLEIGH_CPP` 开关后（默认 on = Phase1 行为不变；
  `=0` 纯 Rust 构建）。默认引擎在 `has_sleigh` 构建下保持 cpp——**门禁全过
  前不退役 C++ 链**（Phase2 纪律）。

### 1.1 镜像语义清单（Rust 后端 vs sleigh_shim/rugra_sleigh.cpp）

| shim 语义 | Rust 后端对应物 | 恒等性证明 |
|---|---|---|
| `RugraLoadImage::loadFill`（cpp:108-133）：无符号模减 `start - base`、越界 `DataUnavailError("Unable to load N bytes at <shortcut><printRaw>")`、前缀复制+补零 | `SharedLoadImage::load_fill` 同算法，message 由 `get_shortcut`+`print_raw` 拼接 | op-for-op 全部 57,817 错误对 message 字节逐字节相等 |
| `RugraPcodeEmit::identityFor`（cpp:172-179）：`VarnodeData*` 指针首见序 identity | kuna 发射 `&pool[range]` 切片（`PcodeCacher::emit` 在 build 完成后遍历，sleigh.cc:776 同序），槽位地址=池指针身份 | identity 字段参与逐 op 对比，零差 |
| `copyVarnode` LOAD/STORE input(0)（cpp:193-203）：const space + size==`sizeof(AddrSpace*)`=8 校验，offset 由 space 指针反查 index，`space_ref=index` | kuna LOSS-015：offset 本就存 manager index；校验 const/size/管理器范围后 `offset=space_ref=index` | wire 值恒等（语料含大量真实 LOAD/STORE） |
| `captureCurrentException`（cpp:296-319）catch 序：Unimpl→BadData→DataUnavail→Sleigh→Lowlevel→Decoder→bad_alloc→std→unknown | `map_kuna_error`：Unimpl（带 instruction_length）/BadData/DataUnavail/Sleigh/Lowlevel/Decoder 直映射；Recov/Parse/Evaluation/ParamUnassigned/JumptableThunk/Java 按上游继承（全部 `: LowlevelError`，error.hh:85/95、opbehavior.hh:30、fspec.hh:64、jumptable.hh:42、ghidra_arch.hh:55）折叠 Lowlevel | 错误 kind+length 在全部错误对恒等 |
| `decode_started` 冻结（set_image/set_context → InvalidState） | 同守卫同错误 | 语义镜像 |
| `num_spaces/space_info`（`space->getType()` 枚举序）/`num_registers/register_info`（`std::map<VarnodeData,string>` 序） | kuna `spacetype` 显式判别值同 space.hh IPTR_*；`get_all_registers` BTreeMap 按 `VarnodeData::operator<`（space index→offset→size 降序）同序 | 目录枚举 5 spaces + 1440 registers 全等 |

### 1.2 与既有 rugra 门禁的兼容性

- `cargo check/test --lib`：C++ 默认构建与 `RUGRA_SLEIGH_CPP=0` 纯 Rust 构建
  双形态全绿（sleigh_ffi 3/3）。
- `examples/sleigh_test`（cpp/rust/default）输出恒等：spaces=5 registers=1440
  step=3。
- 三门禁：annotations 97 文件 ✓ / refs `--all --strict` ✓ / evidence
  self-test 6 cases 4/4 ✓。

## 2. 门禁 ①：op-for-op 恒等（PASS）

仪器：`examples/sleigh_engine_diff.rs`（同进程双引擎，`with_engine` 各建
ctx，同 .sla 同 image 同 pspec 默认）。

方法：每语料**每字节位置**各作为指令起始地址解码一次（覆盖全部前缀/
中缀上下文与错误路径），对比完整观察结果。

语料面（36）：
- LCG 垃圾流 16 KiB（256 值均匀分布，x86 前缀组合压力面）；
- ELF 头 512 B × 6 二进制（Phase0 probe_decode 同款垃圾流面）；
- curl/httpd/virt-ssh-helper/sasquatch/ls 全部 SHF_EXECINSTR 段（.init/
  .plt/.plt.got/.plt.sec/.text/.fini）逐段全量。

| 指标 | 数值 |
|---|---|
| 解码对 | 698,605 |
| 成功对（含 zero-op/多 op/delay 语义） | 640,788 |
| 错误对（kind+length+message 字节） | 57,817 |
| 对比 p-code op 数 | 5,550,599 |
| decode 分歧 | **0** |
| 目录分歧（spaces/registers） | **0** |

代表性覆盖（节选）：httpd .text 318,773 位置 293,437 ok/2,483,681 ops；
sasquatch .text 245,422 位置 227,178 ok/2,054,301 ops；LCG 16,384 位置
14,332 ok。

复现：

```bash
CARGO_TARGET_DIR=/dev/shm/rugra-targets/sleighp2 \
  cargo run --profile fast-release --example sleigh_engine_diff
# → [SUMMARY] ... decode_divergences=0 catalog_divergences=0 / [VERDICT] OP-FOR-OP IDENTICAL
```

## 3. 门禁 ②：E2E 五语料 A/B（PASS，全部字节恒等）

方法：同一 release 二进制（最终代码含 instruction_length 冻结镜像修复），唯一变量
`RUGRA_SLEIGH_ENGINE`（cpp=基线（worktree 基 d4347cd 现态）vs rust），stdout 逐字节 cmp。

| 语料 | 面 | 尺寸 | sha16 | 判定 |
|---|---|---|---|---|
| curl | canon（`examples/curl_decompile`） | 95,842 B | `0d0a369b…` | **IDENTICAL**（尺寸==MERGEBATCH13 新基线 95,842B） |
| httpd | canon（`examples/httpd_decompile`） | 56,219 B | `59b86dea…` | **IDENTICAL**（==MERGEBATCH13 记录 56,219B） |
| vsh | `RUGRA_GEN_MIRROR=1 gen_decompile /usr/bin/virt-ssh-helper` | 49,584 B | `0811f13e…` | **IDENTICAL**（==Phase1 记录 49,584B） |
| sq | `RUGRA_GEN_MIRROR=1 gen_decompile /usr/local/bin/sasquatch` | 2,416,424 B | `a16ca396…` | **IDENTICAL** |
| sqlite3 | `RUGRA_GEN_MIRROR=1 gen_decompile /tmp/sqlite3 --one`，41 均布 idx/2813 函数（本机语料） | 233,520 B | `80fa4e47…` | **IDENTICAL** |

配套（最终代码）：
- `cargo test --lib`：**1777P/0F/5I 双引擎恒等**（cpp 默认 + rust env；rust 0.62s vs
  cpp 1.57s）。
- 投影银行 `tools/verify_projection_bank.sh`：**391/391 MATCH**（冻结锚面，与引擎无关）。
- 三门禁：annotations 97 文件 ✓ / refs `--all --strict` ✓ / evidence self-test
  6 cases strict 4/4 ✓。
- E2E 墙钟（curl canon）：cpp 146.6s vs **rust 130.6s（−11%）**——FFI/C ABI 边界
  消除的真实管线收益。

## 3b. 门禁 ③：性能（decode 吞吐，如实记录三组口径）

| 口径 | C++ 引擎 | Rust 引擎 | 比值 |
|---|---|---|---|
| fast-release 微基准（httpd .text 逐字节 318,773 decodes/2,483,681 ops，单轮） | 8,500 ns/decode（1,091 ns/op） | 7,046–7,098 ns/decode（904–911 ns/op） | Rust ~1.20× 快 |
| release 微基准（同面，4 轮中位数） | ~5,727 ns/decode | ~6,500 ns/decode | C++ ~1.13× 快 |
| E2E 真实管线墙钟（curl canon 全程） | 146.58 s | **130.59 s** | **Rust 1.12× 快** |

结论：decode 吞吐**同量级**（±20% 带内，随 profile/宿主并发负载摆动，无病理性
回退）；端到端墙钟 Rust 引擎稳定更快（免每指令 C ABI 跨界与 C++ 侧 wire 打包）。

## 4. 门禁 ③：性能（数字）

完整三组口径与结论见 §3b（fast-release 微基准 Rust 1.20× 快 / release 微基准
中位数 C++ 1.13× 快 / E2E 墙钟 Rust 1.12× 快——同量级，无病理性回退，
端到端稳定受益于 FFI 边界消除）。

## 5. C++ 退役（门禁全过后执行）

退役面（本车道最终 commit）：

- `build.rs` 删除（21 文件 C++ 运行时编译、`has_sleigh` cfg、DEP_Z zlib 接线、
  ffi-test link-search 一并消失；`[build-dependencies] cc` 移除——capstone-sys
  自带构建,`libz-sys` 保留因 src/compression.rs 直用 zlib）。
- `sleigh_shim/` 删除（C ABI shim 源）。
- `src/sleigh_ffi.rs` 的 `cpp_backend` 模块、wire DTO（RugraVarnodeWire/
  RugraPcodeOpWire）、双链选择机（`SleighEngineKind`/`with_engine`/
  `RUGRA_SLEIGH_ENGINE`）全部删除;公开面收敛为 kuna 引擎直驱
  （`SleighLifter` 面不变）。
- `examples/sleigh_engine_diff.rs` 随 C++ 链退役（双引擎仪器无第二引擎可比;
  存档于退役前 commit `cfeb30c6` 供复现）。
- **保留**：`tools/sweep_sleigh_specs.py` 的 sleigh_opt（oracle 参照仪器,
  自建自用,不经 build.rs）;锁定 oracle C++ 重建侧（各 B2 runner 内嵌）。

### 5.1 fixture 舰队影响审计（重钉纪律）

- **160 个 pinned-commit runner**（`base_file`/`pinned_tree_files` 自
  `rugra_base_commit` 物化快照）:build.rs/sleigh_shim/Cargo.lock 均取自
  git 历史固定 commit,**结构上不受退役影响**。抽查亲证:
  run_action_merge_order_oracle 基线与退役 tip 同判（rc=1 同消息=预存
  GLOBREPIN 族失败,非本 lane 波及）。
- **13 个 live-tree runner**（`snapshot_file` 读现行树）逐个基线亲测:
  - 12 个在基线 d4347cd **本就红**（pin 内部不一致:5 个 sla blob
    `input_commit:path` 解析≠pin 值、6 个 cargo_toml STALE、1 个 doc_varmap
    sha——全为 GLOBREPIN 族预存,亲测 rc=1 记录在案）:退役使其失败点前移
    （快照 build.rs 缺失）,红→红,零回归。
  - 1 个绿（run_debugproto_unknown_model_oracle.sh）在退役树 tip **复跑
    MATCH**（rc=0,纯 Rust 构建,B2 直证）。
- 结论:**基线绿且 tip 红的面=零**,本 lane 重钉欠账=零。12 红面 runner 的
  复活需 pin 修复+C++ 胶水手术双管,登记族票 `SLEIGH-RETIREE-FLEET-REPIN-0001`
  （与 GLOBREPIN 族波次合并调度）。

### 5.2 退役树验证（纯 Rust 构建,无 build.rs）

- `cargo check/test --lib`:编译零错;测试 1776P/0F/5I（−1=随 wire DTO 删除
  的布局单测）。
- `cargo build --release --example {curl,httpd,gen}_decompile` 正常
  （无 stdc++/z 链接需求,C ABI 符号全消）。
- canon curl/httpd 与退役前 cpp 基线字节恒等（§3 方法,cmp 零差）。
- bank 391/391 + 三门禁绿。
- `tools/run_debugproto_unknown_model_oracle.sh` MATCH（§5.1）。

## 6. 残差与登记

- 见 TODO_BOARD `SLEIGH-RUSTIFY-PHASE2-0001` 行（证据全量）与
  `SLEIGH-RETIREE-FLEET-REPIN-0001` 族票。
- Phase0 §7.1 去重决策项（kuna-sleigh 与 rugra 既有 marshal/space/pcoderaw
  类型统一）：**维持 Phase1 决策**——vendored crate 保持 byte-identical
  供审计，类型统一推迟（独立票,非本票写域）。
- PHASE3（iced 退役切换门）按 roadmap §5/§6 排队（A/G 残差族 P-1 可检验
  预测:换源后行数只能改善或不变）。
