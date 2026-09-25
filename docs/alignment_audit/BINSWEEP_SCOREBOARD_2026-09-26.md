# BINSWEEP 记分板 — 系统二进制健壮性广扫（2026-09-26）

车道 PANICSWEEP（wt/panicsweep，基 = master `d0e27c14`；oracle = Ghidra 12.0.4 `e40ed130`
锁定，本车道零 src/ 改动）。通用性探针：**50+ 个从未调参的系统二进制**过 Rugra 完整
反编译管线（gen_decompile 裸面契约），逐函数分类 panic / error / timeout / crash。

## 0. 运行指纹（可复现）

| 项 | 值 |
|---|---|
| 驱动 | `examples/bin_sweep.rs`（commit `169cd839` + flush 修复 `49897151`） |
| 构建 | `cargo build --profile fast-release --example bin_sweep`（CARGO_TARGET_DIR 任意） |
| 样本清单 | `docs/alignment_audit/binsweep_manifest_2026-09-26.jsonl`（66 条，含 sha256+ELF 特征） |
| 复现命令 | `bin_sweep --manifest docs/alignment_audit/binsweep_manifest_2026-09-26.jsonl --max-funcs 24 --func-timeout 30 --binary-budget 120 --jobs 8 --out-dir <dir>` |
| 选样规则 | BFD 函数符号发现（.symtab ∪ .dynsym 定义 FUNC + PLT JUMP_SLOT 桩，去重排序），每二进制取**最大 24 个**（size 降序、地址平局） |
| 单函数超时 | 30s（`timeout -k 10s` 外层进程隔离）；单二进制墙预算 120s，余量 <3s 的剩余函数如实记 `budget-skipped` |
| panic 捕获 | worker 进程内 256MB 大栈线程 + panic hook 记录 file:line + join Err 分类；worker-failure 重试 1 次再归因 |
| 数据完整性 | run1（/dev/shm 满导致尾部截断）+ run1b（6 个受影响二进制重扫，驱动已加 flush 响亮失败）合并 = 本表口径；functions.jsonl 1526 行全 JSON 有效 |

> run1/run1b 原始数据：`/tmp/binsweep-merged/{functions,results,summary}.jsonl`（合并口径）；
> run1 原始件 `/dev/shm/rugra-tests/panicsweep/run1/`。非 ok 结果的完整 worker stderr 存
> `<out-dir>/stderr/<bin>__<idx>.log`。

## 1. 总分

| 指标 | 值 |
|---|---|
| 清单二进制 | 66（9 类：network/compression/crypto/interpreter/shell-util/binutils-dev/system-admin/misc-app/lib） |
| 有函数可扫 | 65（busybox = 静态 stripped，零符号，如实记 `no-functions`） |
| 发现函数总数 | 27 158 |
| 选样函数总数 | 1 526 |
| **实际执行** | **1 526**（ok 1 370 + panic 35 + timeout 20 + error 3 + budget-skipped 98） |
| **ok 率（执行内）** | **89.8 %**（1370/1526） |
| panic 率 | 2.3 %（35/1526） |
| timeout 率 | 1.3 %（20/1526） |
| error 率 | 0.2 %（3/1526） |
| budget-skipped 率 | 6.4 %（98/1526，12 个慢二进制吃满 120s 预算） |
| crash（SIGSEGV/SIGABRT/栈溢出） | **0** |
| 全净二进制（所有执行函数 ok） | 51/65 |
| worker 协议失败 | 0（重试后仍 0） |

**一句话结论**：进程级健壮性良好（零 crash、零 worker-failure），但 **panic 是主要失败面
（35/58 非 ok = 60 %），其中 91 %（32/35）是同一个已知族 PRETTYFLUSH**；唯一成规模的新
panic 族是 ip 的 RuleSubCommute→add_descend（3 例）；新 error 族 = python3.10 跳表目的地
未链接（3 例）；超时族 20 例呈两个子形态（collapse 重启循环 / 大函数不收敛）。

## 2. 族分布（35 panic + 3 error + 20 timeout）

| 族 | 计数 | 二进制数 | 票 |
|---|---|---|---|
| `K:PRETTYFLUSH-3946`（panic at prettyprint.rs:3946, indentstack 空 unwrap） | 32 fn / 10 bin | lvm 8, python3.10 5, libzstd 4, libz 3, ip/bash/libcrypto/libgcrypt/libgmp/rsyslogd 各 2 | **已知** SQATTR-PENDINGBRACE-IDENTITY-0001（本扫 = curl/httpd/vsh/sq 之外首个大语料证据，10 二进制 32 函数） |
| `T:TIMEOUT`（30s 不终止） | 20 fn / 10 bin | dig 4, e2fsck 3, libzstd 3, python3.10 2, ip 2, libbz2 2, bash/perl/libgmp/rsyslogd 各 1 | **新票** BINSWEEP-COLLAPSE-RESTART-HANG-0001 |
| `NEW:PANIC:varnode.rs:2716`（Free varnode has multiple descendants） | 3 fn / 1 bin | ip: print_addrinfo(206) / do_iptunnel(246) / print_neigh(248) | **新票** BINSWEEP-SUBCOMMUTE-FREEVARNODE-0001（栈顶 RuleSubCommute::apply_op——**非** RULEACTION-SUBRIGHT-UNLINK-0001 的 RuleSubRight 生产者） |
| `E:FLOW-JTDEST-UNLINKED`（flow: Jumptable destination not linked） | 3 fn / 1 bin | python3.10: PyUnicode_FromFormatV(1027) / PyUnicode_Format(1253) / _PyUnicode_DecodeUnicodeEscapeInternal2(1288) | **新票** BINSWEEP-JTDEST-UNLINKED-0001 |

已知族对照（本扫零命中，回退信号良好）：`K:MERGE-FORCEDINTERSECT`（sasquatch 复现
验证过捕获机制，66 样本 0 命中）、`K:DBLHI-UNINSERT-4984`（已修，0 命中）、
`K:NULLLOCALTYPE`（0 命中）。

## 3. 分类×类别矩阵（执行函数）

| 类别 | ok | panic | timeout | error | skip |
|---|---|---|---|---|---|
| binutils-dev (8 bin) | 192 | 0 | 0 | 0 | 0 |
| compression (8) | 186 | 0 | 5 | 0 | 1 |
| crypto (4) | 96 | 0 | 0 | 0 | 0 |
| interpreter (6) | 82 | 5 | 3 | 3 | 17 |
| lib (10) | 148 | 5 | 5 | 0 | 2 |
| misc-app (6) | 120 | 0 | 0 | 0 | 0 |
| network (10) | 197 | 5 | 6 | 0 | 32 |
| shell-util (6) | 128 | 2 | 1 | 0 | 13 |
| system-admin (8) | 136 | 8 | 0 | 0 | 33 |

binutils 全家（objdump/ld/as/ar…）、crypto、misc-app 三类**零缺陷**；system-admin 的 lvm
单二进制贡献 8 panic（全 PRETTYFLUSH）。

## 4. Top 嫌疑样本（复现命令在案）

最强复现（最小确定性）：

```bash
# 新 panic 族（3s 内炸，栈顶已取）：
bin_sweep --sweep-one /usr/sbin/ip 206            # print_addrinfo → RuleSubCommute→op_set_input→add_descend
RUST_BACKTRACE=1 gen_decompile /usr/sbin/ip --one 206   # 默认 hook 版栈（取栈用）

# 新 error 族：
bin_sweep --sweep-one /usr/bin/python3.10 1027    # PyUnicode_FromFormatV: Jumptable destination not linked

# 新超时族（最小 271 字节函数 30s 不终止；45s 亲测仍在 [COLLAPSE] ruleBlockGoto 循环）：
timeout 30 bin_sweep --sweep-one /usr/bin/dig 255  # warn() 271B
timeout 30 bin_sweep --sweep-one /usr/bin/dig 254  # get_reverse() 351B（同形）

# 已知族证据（PRETTYFLUSH）：
bin_sweep --sweep-one /usr/sbin/lvm <idx>         # lvm 8 例：pvcreate_each_device 等
```

Top 嫌疑二进制（非 ok 函数数，P=panic/T=timeout/E=error）：lvm 8P、python3.10 5P+2T+3E、
libzstd 4P+3T、ip 2P+3P(vn)+2T、dig 4T、e2fsck 3T、bash 2P+1T、libz 3P、
libcrypto/libgcrypt/libgmp/rsyslogd 各 2P（libgmp 另有 1T）。

超时族子形态（stderr 取证，`stderr/` 归档）：
- **collapse 重启循环**（尾行 `[COLLAPSE] … ruleBlockGoto: wrapped block` 反复）：dig×4、
  e2fsck main(353，run1 形态；run1b 复扫未再超时=边界态，如实记)、python3.10
  PyType_Ready/_Py_dg_dtoa、rsyslogd yylex；
- **finalize 后挂**（尾行 `finalize_structure: N -> M` 后无进展）：ip print_linkinfo/do_netns、
  bash execute_command_internal、perl Perl_yyparse、libbz2 BZ2_blockSort(486B!)/
  BZ2_hbMakeCodeLengths(1174B)、libgmp __gmpn_mul、libzstd 三个 ZSTD_compressBlock_* 变体；
- **BlockInfLoop 构建后挂**（尾行 `[BLOCKSTRUCT] inf loop at block N`）：e2fsck_pass2(372)、
  e2fsck_process_bad_inode(373)。

## 5. 驱动资产（可复用性）

- `examples/bin_sweep.rs`：输入任意 ELF 路径或 manifest JSONL；`--sweep-one` 单函数模式
  （对拍/取栈入口）；家族分类器内建（K:/NEW:/E:/T:/C: 五键）；输出 functions/results/
  summary/run.meta 四件 + 非 ok 的 stderr 全档。
- manifest 生成脚本（类别清单+sha256+ELP 特征）：`/dev/shm/rugra-tests/panicsweep/
  select_samples.py`（scratch；类目表内嵌，重跑即得同清单）。
- 合并/再分类脚本：`/tmp/binsweep-run1b/merge_and_summarize.py`（含与 Rust 分类器同语义
  的 python 镜像）。

## 6. 边界与诚实声明

- 30s/120s 预算下的 budget-skipped（98 fn / 12 bin）**不是缺陷分类**，是预算诚实记录；
  其中 perl/bash/e2fsck 等的二进制级预算被前面函数的超时吃掉。
- ok = 打印出非空 C 文本且进程正常退出，**未与 Ghidra oracle 对拍**（本车道是健壮性探针，
  不是对齐验证；文本正确性由既有 curl/httpd/sq 差分车道承重）。
- busybox（静态 stripped）零符号不可扫——非驱动缺陷；如需覆盖此类需 ELF 入口点+调用图
  发现层（DISCOV 形态），超出本扫范围。
- panic 计数全部来自进程内 catch（worker 正常退出、sentinel 上报）；零 crash 意味着
  256MB 大栈下无栈溢出、无 FFI abort。
