# Ghidra 黄金输出集（Golden Outputs）

本目录存放从**真实 Ghidra** 跑出的反编译输出，作为 `tools/compare_ghidra.py` 差分测试的基准（AGENTS.md 铁律 11）。

## 文件

| 文件 | 来源二进制 | Ghidra 版本 | 生成日期 |
|---|---|---|---|
| `ghidra_curl.c` | `examples/curl` | Ghidra 11.3.2 PUBLIC | 2026-06-29 |

## 生成方法

```bash
# 用 Ghidra analyzeHeadless 反编译, 导出 C 代码
# (详见 tools/ghidra_decompile_all.py)
python tools/ghidra_decompile_all.py examples/curl --output /tmp/ghidra_curl_raw.c

# 清洗: 剥离前 ~124 行 INFO 日志噪音, 从第一个 "/* ---- 0x" 函数头开始
# (ghidra_decompile_all.py 的输出格式: 前缀是 Ghidra 启动日志, 之后是 C 代码)
tail -n +<FIRST_HEADER_LINE> /tmp/ghidra_curl_raw.c > tests/golden/ghidra_curl.c
```

## 格式约定

- 函数头格式：`/* ---- 0xADDR: NAME (SIZE bytes) ---- */`（Rugra 与 Ghidra 两边相同）
- 地址用 Ghidra 绝对地址（如 `0x1025a0`），Rugra 用相对偏移（`0x25a0`），差值恒为 `0x100000`
- 函数名：Ghidra 会剥离 GCC 优化后缀（`.constprop.0`/`.part.0`/`.isra.0`），Rugra 保留；`compare_ghidra.py` 的 `strip_gcc_suffix` 处理此差异

## 重新生成

当升级 Ghidra 版本或更换测试二进制时，重新跑生成命令并更新本目录。**不要手工编辑黄金输出**——它们必须反映真实 Ghidra 的输出。

## 已知差异（非缺陷，compare_ghidra.py 会归一化处理）

- Ghidra 有 PLT thunk / 外部符号 stub（`FUN_`/`free`/`strcpy` 等 1-byte stub），Rugra 不输出
- Ghidra 用 `PTR_`/`DAT_`/`LAB_`/`(code*)` 占位，Rugra 不用
- 变量命名：Ghidra 用类型化连续编号（`cVar1,lVar2,bVar3`）+ 语义名（`config`）；Rugra 用 `StackX_N` + 编号可能非连续（181538f bug，待修）

这些差异在 `compare_ghidra.py` 的 `normalize_skeleton`/`strip_noise` 中归一化，不产生 diff 噪音。
