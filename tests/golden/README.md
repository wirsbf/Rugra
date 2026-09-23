# Ghidra 黄金输出集（Golden Outputs）

本目录存放从**真实 Ghidra** 跑出的反编译输出，作为 `tools/compare_ghidra.py` /
`tools/func_gap_audit.py` / `tools/align_check.py` 差分测试的基准（AGENTS.md 铁律 11）。

## 文件

| 文件 | 来源二进制 | Ghidra 版本 | 生成日期 | 说明 |
|---|---|---|---|---|
| `ghidra_curl.c` | `examples/curl` | Ghidra 11.3.2 PUBLIC | 2026-06-29 | 清理版（尾部 4 行 INFO 噪音已剥） |
| `ghidra_curl.11.3.2.c` | `examples/curl` | Ghidra 11.3.2 PUBLIC | 2026-06-29 | 原始存档（含尾部 INFO 噪音，留底） |
| `ghidra_curl_1204.c` | `examples/curl`(sha `8af50bca…`) | 12.0.4(e40ed130) | 2026-08-15 | **canonical 基线**:analyzeHeadless 默认分析+postScript,124 函数;provenance.json 含逐函数 ledger |
| `ghidra_curl_1204.direct-runner.c` | 同上 | 12.0.4(e40ed130) | 2026-08-15 | **库级基线**:锁定 cpp 树+BFD 单函数 hermetic 契约(RUGRA_MIRROR 同契约),74 函数;地址=BFD VMA(base 0),对拍须 `--base 0` |
| `ghidra_httpd_1204.c` | `examples/httpd`(sha `805f89cd…`) | 12.0.4(e40ed130) | 2026-08-15 | canonical,2010 函数 |
| `ghidra_httpd_1204.direct-runner.c` | 同上 | 12.0.4(e40ed130) | 2026-08-15 | 库级基线,790 函数;`--base 0` |

双基线语义与量化裁决见 `docs/alignment_docs/GOLDEN_CONTRACT_QUANT_2026-09-23.md`
(GOLDEN-CONTRACT-PUSHABSORB-0001):canonical=analyzeHeadless 桥接层产物(push 存储
吸收、分析器原型/类型/引用);direct-runner=库级 BFD 契约(保留 `xStack_50 = …;`
类 push 打印与 `xunknown*` 类型)。库级语料是 canonical 的子集(59.7%/39.3%,
BFD 符号表发现上限)。

## 格式约定

- 函数头格式：`/* ---- 0xADDR: NAME (SIZE bytes) ---- */`（Rugra 与 Ghidra 两边相同）
- 地址用 Ghidra 绝对地址（如 `0x1025a0`），Rugra 用相对偏移（`0x25a0`），差值恒为 `0x100000`
- 函数名：Ghidra 会剥离 GCC 优化后缀（`.constprop.0`/`.part.0`/`.isra.0`），Rugra 保留；`compare_ghidra.py` 的 `strip_gcc_suffix` 处理此差异
- 文件首行必须是函数头（`/* ---- 0x`），末行必须是 `}` 或空——**不得**含 Ghidra INFO/REPORT 日志行

## 重新生成

```bash
# 需要"已安装/已 build"的 Ghidra distribution（不能是源码 repo）。
# 本机 D:/ghidra/rugra/ghidra 是未 build 的 12.1 源码 repo，跑不了 headless；
# 待装好 distribution 后，用本命令一键重生成：
python tools/regen_golden.py --binary examples/curl --ghidra <path-to-analyzeHeadless.bat>
```

`tools/regen_golden.py` 驱动 `analyzeHeadless` 跑改写后的
`tools/ghidra_decompile_all.py`（postScript **写文件**而非 print stdout，
根因消除 C 输出与 Ghidra INFO 日志的交错），写后校验首行/末行/函数头数。

**不要手工编辑黄金输出**——它们必须反映真实 Ghidra 的输出。唯一的例外是
从原始存档剥除 INFO 日志噪音（如本次 `ghidra_curl.c` 从 `.11.3.2.c` 剥除尾部 4 行）。

## 已知差异（非缺陷，compare_ghidra.py 会归一化处理）

- Ghidra 有 PLT thunk / 外部符号 stub（`FUN_`/`free`/`strcpy` 等 1-byte stub），Rugra 不输出
- Ghidra 用 `PTR_`/`DAT_`/`LAB_`/`(code*)` 占位，Rugra 不用
- 变量命名：Ghidra 用类型化连续编号（`cVar1,lVar2,bVar3`）+ 语义名（`config`）；Rugra 用 `StackX_N` + 编号可能非连续（181538f bug，待修）

这些差异在 `compare_ghidra.py` 的 `normalize_skeleton`/`strip_noise` 中归一化，不产生 diff 噪音。

## 版本漂移

当前 golden 是 11.3.2 产出，本机源码 repo 是 12.1（未 build）。升级到 12.1
重生成后，所有函数的 golden 输出都会变，差分基线会重置——这是预期行为。
